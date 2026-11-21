use crate::tools::approvals::ApprovalGate;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::process::{ExitStatus, Stdio};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::{oneshot, Semaphore},
};

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_SHELL_OUTPUT: usize = 8 * 1024;
#[cfg(unix)]
const MAX_ACTIVE_SHELLS: usize = 8;
#[cfg(unix)]
static SHELL_PERMITS: OnceLock<Arc<Semaphore>> = OnceLock::new();

// Drain both pipes concurrently, retaining no more than MAX_SHELL_OUTPUT
// bytes per stream. Extra output is discarded rather than buffered; pipe
// writers cannot deadlock because their output is still consumed.
async fn read_bounded_output<R: AsyncRead + Unpin>(
    mut reader: R,
) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::with_capacity(MAX_SHELL_OUTPUT);
    let mut chunk = [0_u8; 4096];
    let mut truncated = false;
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok((retained, truncated));
        }
        let remaining = MAX_SHELL_OUTPUT.saturating_sub(retained.len());
        let keep = remaining.min(n);
        retained.extend_from_slice(&chunk[..keep]);
        if keep < n {
            truncated = true;
        }
    }
}

// Scoped to the already-canonicalized grant path by the caller. This pins
// the *leaf* inode through a single FD, preventing path replacement between
// metadata and bytes. Parent-directory races still belong to #34.
fn read_scoped_file(path: &Path) -> Result<String, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|_| "Cannot open approved file safely")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect approved file")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("Not a regular file or file exceeds 64 KiB".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err("Hard-linked files cannot be read as a scoped grant".into());
        }
    }

    // Protect even if the opened regular file grows after metadata inspection.
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read approved file")?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("File exceeds 64 KiB limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "Only UTF-8 files are supported".into())
}

// An approved command always starts a fresh Unix process group. The group's
// numeric ID is the unreaped child PID: keep the Child handle and do NOT wait
// before signalling the entire group. Reaping early would allow PID/PGID reuse.
// Children that create a new session can escape; this is not an OS sandbox.
#[cfg(unix)]
struct ShellProcessOwner {
    child: Child,
    pgid: libc::pid_t,
    reaped: bool,
}

#[cfg(unix)]
impl ShellProcessOwner {
    fn new(child: Child) -> Result<Self, String> {
        let pid = child.id().ok_or("Approved shell has no process ID")?;
        let pgid =
            libc::pid_t::try_from(pid).map_err(|_| "Approved shell process ID is out of range")?;
        if pgid <= 1 {
            return Err("Approved shell process group is unsafe".into());
        }
        Ok(Self {
            child,
            pgid,
            reaped: false,
        })
    }

    fn signal_group(&self, signal: libc::c_int) {
        // SAFETY: process_group(0) creates a new group whose id is the owned
        // child's PID. We never reap that child until AFTER the final KILL,
        // so this negative group ID cannot be reused by an unrelated group.
        // A signal only targets group members, never the app or its parent.
        unsafe {
            libc::kill(-self.pgid, signal);
        }
    }

    async fn terminate_and_reap(mut self) -> std::io::Result<ExitStatus> {
        // TERM is best effort; shell descendants can ignore it. The retained
        // unreaped leader pins the PGID through both signals. A bounded grace
        // period is followed by unconditional KILL before wait/reap.
        self.signal_group(libc::SIGTERM);
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.signal_group(libc::SIGKILL);
        let status = tokio::time::timeout(Duration::from_secs(2), self.child.wait())
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "shell reap timed out")
            })??;
        self.reaped = true;
        Ok(status)
    }
}

#[cfg(unix)]
impl Drop for ShellProcessOwner {
    fn drop(&mut self) {
        if !self.reaped {
            // A runtime shutdown or task panic still sends one final group
            // KILL while the child PID is owned and not reaped. Tokio's
            // kill_on_drop provides a second direct-child fallback.
            self.signal_group(libc::SIGKILL);
        }
    }
}

// The HTTP caller owns the cancellation sender, not the child. Aborting its
// request immediately closes the sender and wakes this independent bounded
// worker, which owns the child/group through cleanup and wait/reap.
#[cfg(unix)]
async fn run_approved_shell(command: String, directory: PathBuf) -> Result<Value, String> {
    // This owner-only limit is required even before the separate shared API
    // dispatch gate (#100) merges. Never spawn unbounded cleanup workers.
    let permit = SHELL_PERMITS
        .get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_SHELLS)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| "Approved shell worker capacity exceeded")?;
    let (cancel_tx, cancel_rx) = oneshot::channel::<()>();
    let (result_tx, result_rx) = oneshot::channel();
    tokio::spawn(async move {
        let _permit = permit; // Released only after complete group cleanup.
        let _ = result_tx.send(run_shell_owned(command, directory, cancel_rx).await);
    });
    let result = result_rx
        .await
        .map_err(|_| "Approved command lifecycle task stopped")?;
    drop(cancel_tx);
    result
}

#[cfg(unix)]
async fn run_shell_owned(
    command: String,
    directory: PathBuf,
    cancel_rx: oneshot::Receiver<()>,
) -> Result<Value, String> {
    run_shell_owned_with_deadline(command, directory, cancel_rx, Duration::from_secs(15)).await
}

// Tests inject a short deadline; production always uses the full 15 seconds.
#[cfg(unix)]
async fn run_shell_owned_with_deadline(
    command: String,
    directory: PathBuf,
    mut cancel_rx: oneshot::Receiver<()>,
    deadline: Duration,
) -> Result<Value, String> {
    let mut process = Command::new("/bin/sh");
    process
        .arg("-lc")
        .arg(&command)
        .current_dir(directory)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        // Use Tokio's supported Unix API, not unsafe fork/pre_exec in Tauri.
        .process_group(0);
    let child = process
        .spawn()
        .map_err(|_| "Cannot launch approved command")?;
    let mut owner = ShellProcessOwner::new(child)?;
    let stdout = owner
        .child
        .stdout
        .take()
        .ok_or("Cannot capture command stdout")?;
    let stderr = owner
        .child
        .stderr
        .take()
        .ok_or("Cannot capture command stderr")?;

    // Drain stdout/stderr concurrently. The shell is intentionally NOT reaped
    // in this capture future: a leader-exits-first command can leave pipe-
    // holding descendants, and the unreaped PID pins ownership of the PGID.
    let capture = tokio::select! {
        biased;
        _ = &mut cancel_rx => Err("Command cancelled".to_owned()),
        output = tokio::time::timeout(deadline, async {
            tokio::try_join!(
                read_bounded_output(stdout),
                read_bounded_output(stderr)
            )
        }) => match output {
            Ok(Ok(streams)) => Ok(streams),
            Ok(Err(_)) => Err("Command execution or output capture failed".into()),
            Err(_) => Err("Command timed out".into()),
        },
    };

    // Always kill/reap the owned group, including when EOF happens before a
    // background descendant exits or on cancellation, timeout, reader error.
    // A shell closing both pipes while continuing to run is deliberately
    // terminated; there is no unowned daemonization from this tool.
    let status = owner
        .terminate_and_reap()
        .await
        .map_err(|_| "Command process group cleanup failed");
    let (stdout, stderr) = capture?;
    let status = status?;
    Ok(json!({
        "exit_code": status.code(),
        "stdout": String::from_utf8_lossy(&stdout.0),
        "stderr": String::from_utf8_lossy(&stderr.0),
        "output_truncated": stdout.1 || stderr.1
    }))
}

#[cfg(not(unix))]
async fn run_approved_shell(_command: String, _directory: PathBuf) -> Result<Value, String> {
    Err("Approved shell execution requires Unix process-group isolation".into())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

pub struct ToolRegistry {
    roots: RwLock<Vec<PathBuf>>,
    gate: Arc<ApprovalGate>,
}

impl ToolRegistry {
    pub fn new(roots: Vec<PathBuf>, gate: Arc<ApprovalGate>) -> Self {
        Self {
            roots: RwLock::new(roots),
            gate,
        }
    }

    pub fn is_known(tool: &str) -> bool {
        matches!(tool, "filesystem__read_file" | "bash__run")
    }

    pub fn canonical_roots(roots: &[String]) -> Result<Vec<PathBuf>, String> {
        let mut canonical = Vec::new();
        for root in roots {
            let path = std::fs::canonicalize(root).map_err(|_| format!("Invalid root: {root}"))?;
            if !path.is_dir() {
                return Err(format!("Not a directory: {root}"));
            }
            if !canonical.contains(&path) {
                canonical.push(path);
            }
        }
        Ok(canonical)
    }

    pub fn set_roots(&self, roots: Vec<PathBuf>) {
        *self.roots.write().expect("roots lock poisoned") = roots;
    }

    fn allowed_path(&self, requested: &Path) -> Result<PathBuf, String> {
        let resolved = requested
            .canonicalize()
            .map_err(|e| format!("Path not accessible: {e}"))?;
        let permitted = self
            .roots
            .read()
            .expect("roots lock poisoned")
            .iter()
            .any(|root| resolved.starts_with(root));
        if !permitted {
            return Err("Path outside granted roots".into());
        }
        Ok(resolved)
    }

    pub fn list(&self) -> Vec<Value> {
        vec![
            json!({"type":"function","function":{"name":"filesystem__read_file","description":"Read a UTF-8 file (64 KiB maximum) beneath a user-granted root.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}}}),
            json!({"type":"function","function":{"name":"bash__run","description":"Run a shell command in a granted directory, with an interactive approval gate and 15-second timeout.","parameters":{"type":"object","properties":{"command":{"type":"string"},"cwd":{"type":"string"}},"required":["command","cwd"],"additionalProperties":false}}}),
        ]
    }

    pub async fn invoke(&self, call: ToolCall) -> Result<Value, String> {
        if !Self::is_known(&call.name) {
            return Err("Unknown tool".into());
        }
        match call.name.as_str() {
            "filesystem__read_file" => {
                let input: ReadInput = serde_json::from_value(call.arguments)
                    .map_err(|_| "Expected { path: string }".to_owned())?;
                let path = self.allowed_path(Path::new(&input.path))?;
                self.gate
                    .require("filesystem__read_file", &format!("Read {}", path.display()))
                    .await?;
                // File open/read can block on filesystem I/O. Keep the
                // verified handle and 64 KiB bound together off the reactor.
                let read_path = path.clone();
                let text = tokio::task::spawn_blocking(move || read_scoped_file(&read_path))
                    .await
                    .map_err(|_| "Approved file read task failed")??;
                Ok(json!({ "path": path, "content": text }))
            }
            "bash__run" => {
                let input: RunInput = serde_json::from_value(call.arguments)
                    .map_err(|_| "Expected { command: string, cwd: string }".to_owned())?;
                if input.command.trim().is_empty() || input.command.len() > 4096 {
                    return Err("Invalid shell command length".into());
                }
                let directory = self.allowed_path(Path::new(&input.cwd))?;
                if !directory.is_dir() {
                    return Err("cwd must be a directory".into());
                }
                self.gate
                    .require(
                        "bash__run",
                        &format!("{} (cwd: {})", input.command, directory.display()),
                    )
                    .await?;
                run_approved_shell(input.command, directory).await
            }
            _ => Err("Unknown tool".into()),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadInput {
    path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RunInput {
    command: String,
    cwd: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::approvals::{ApprovalGate, Policy};
    use std::collections::HashMap;
    #[tokio::test]
    async fn filesystem_root_and_symlink_guard() {
        let allowed = tempfile::tempdir().unwrap();
        let denied = tempfile::tempdir().unwrap();
        std::fs::write(allowed.path().join("ok.txt"), "ok").unwrap();
        std::fs::write(denied.path().join("secret.txt"), "secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(
            denied.path().join("secret.txt"),
            allowed.path().join("link.txt"),
        )
        .unwrap();
        let reg = ToolRegistry::new(
            vec![allowed.path().canonicalize().unwrap()],
            ApprovalGate::new(HashMap::new()),
        );
        let result = reg
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path":allowed.path().join("ok.txt")}),
            })
            .await
            .unwrap();
        assert_eq!(result["content"], "ok");
        assert!(reg
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path":denied.path().join("secret.txt")})
            })
            .await
            .is_err());
        #[cfg(unix)]
        assert!(reg
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path":allowed.path().join("link.txt")})
            })
            .await
            .is_err());
    }

    #[test]
    fn scoped_fd_read_has_64_kib_boundary_and_utf8_validation() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("granted.txt");
        std::fs::write(&file, vec![b'x'; MAX_FILE_BYTES as usize]).unwrap();
        let exact = read_scoped_file(&file).unwrap();
        assert_eq!(exact.len(), MAX_FILE_BYTES as usize);
        std::fs::write(&file, vec![b'x'; MAX_FILE_BYTES as usize + 1]).unwrap();
        assert!(read_scoped_file(&file).is_err());
        std::fs::write(&file, [0xff_u8, 0xfe_u8]).unwrap();
        assert_eq!(
            read_scoped_file(&file).unwrap_err(),
            "Only UTF-8 files are supported"
        );
        assert!(read_scoped_file(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn scoped_fd_read_rejects_symlink_and_hardlink_leaf() {
        let dir = tempfile::tempdir().unwrap();
        let approved = dir.path().join("approved.txt");
        let symlink = dir.path().join("symlink.txt");
        let hardlink = dir.path().join("hardlink.txt");
        std::fs::write(&approved, b"allowed").unwrap();
        std::os::unix::fs::symlink(&approved, &symlink).unwrap();
        assert!(read_scoped_file(&symlink).is_err());
        std::fs::hard_link(&approved, &hardlink).unwrap();
        assert!(read_scoped_file(&hardlink).is_err());
        assert!(read_scoped_file(&approved).is_err());
        std::fs::remove_file(&hardlink).unwrap();
        assert_eq!(read_scoped_file(&approved).unwrap(), "allowed");
    }

    #[tokio::test]
    async fn stdout_and_stderr_drains_are_bounded_without_deadlock() {
        use tokio::io::AsyncWriteExt;
        let (mut stdout_writer, stdout_reader) = tokio::io::duplex(1024);
        let (mut stderr_writer, stderr_reader) = tokio::io::duplex(1024);

        let stdout_producer = tokio::spawn(async move {
            for _ in 0..256 {
                stdout_writer.write_all(&[b'x'; 4096]).await.unwrap();
            }
            stdout_writer.shutdown().await.unwrap();
        });
        let stderr_producer = tokio::spawn(async move {
            for _ in 0..256 {
                stderr_writer.write_all(&[b'y'; 4096]).await.unwrap();
            }
            stderr_writer.shutdown().await.unwrap();
        });

        let (stdout, stderr) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(
                read_bounded_output(stdout_reader),
                read_bounded_output(stderr_reader)
            )
        })
        .await
        .expect("both streams should drain rather than deadlock")
        .unwrap();
        stdout_producer.await.unwrap();
        stderr_producer.await.unwrap();
        assert_eq!(stdout.0.len(), MAX_SHELL_OUTPUT);
        assert_eq!(stderr.0.len(), MAX_SHELL_OUTPUT);
        assert!(stdout.1 && stderr.1);
        assert!(stdout.0.iter().all(|byte| *byte == b'x'));
        assert!(stderr.0.iter().all(|byte| *byte == b'y'));
    }

    #[tokio::test]
    async fn output_truncation_detects_exact_byte_boundary() {
        use tokio::io::AsyncWriteExt;
        let (mut exact_writer, exact_reader) = tokio::io::duplex(MAX_SHELL_OUTPUT + 1);
        exact_writer
            .write_all(&vec![b'a'; MAX_SHELL_OUTPUT])
            .await
            .unwrap();
        drop(exact_writer);
        let exact = read_bounded_output(exact_reader).await.unwrap();
        assert_eq!(exact.0.len(), MAX_SHELL_OUTPUT);
        assert!(!exact.1);

        let (mut larger_writer, larger_reader) = tokio::io::duplex(MAX_SHELL_OUTPUT + 1);
        larger_writer
            .write_all(&vec![b'b'; MAX_SHELL_OUTPUT + 1])
            .await
            .unwrap();
        drop(larger_writer);
        let larger = read_bounded_output(larger_reader).await.unwrap();
        assert_eq!(larger.0.len(), MAX_SHELL_OUTPUT);
        assert!(larger.1);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn approved_shell_group_returns_bounded_output_and_reaps_leader() {
        let dir = tempfile::tempdir().unwrap();
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            run_approved_shell(
                "printf 'hello'; printf 'world' >&2".into(),
                dir.path().to_path_buf(),
            ),
        )
        .await
        .expect("ordinary approved command should not hang")
        .unwrap();
        assert_eq!(response["stdout"], "hello");
        assert_eq!(response["stderr"], "world");
        assert_eq!(response["exit_code"], 0);
        assert_eq!(response["output_truncated"], false);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn cancelling_shell_owner_kills_descendant_even_after_shell_leader_exits() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("descendant-ticks");
        // The outer /bin/sh exits immediately, leaving an inner shell in
        // the SAME PGID holding stdout/stderr open. The inner shell ignores
        // TERM and writes an observable heartbeat; SIGKILL must stop it.
        let command = format!(
            "sh -c 'trap \"\" TERM; while :; do printf x >> \"{}\"; printf y; sleep 0.02; done' & exit 0",
            marker.display()
        );
        let handle = tokio::spawn(run_approved_shell(command, dir.path().to_path_buf()));
        tokio::time::timeout(Duration::from_secs(5), async {
            while std::fs::metadata(&marker).map_or(true, |meta| meta.len() < 2) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("descendant never started");
        // Aborting an HTTP request drops its cancellation sender. The
        // lifecycle worker MUST remain alive to kill group and reap leader.
        handle.abort();
        let _ = handle.await;
        tokio::time::sleep(Duration::from_millis(400)).await;
        let stopped_len = std::fs::metadata(&marker).unwrap().len();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(
            std::fs::metadata(&marker).unwrap().len(),
            stopped_len,
            "descendant kept writing after caller cancellation"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_timeout_terminates_infinite_streams_without_unbounded_capture() {
        let dir = tempfile::tempdir().unwrap();
        let (_cancel_tx, cancel_rx) = oneshot::channel::<()>();
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            run_shell_owned_with_deadline(
                "while :; do printf x; printf y >&2; done".into(),
                dir.path().to_path_buf(),
                cancel_rx,
                Duration::from_millis(200),
            ),
        )
        .await
        .expect("timeout cleanup must finish even with infinite stdout and stderr")
        .unwrap_err();
        assert_eq!(result, "Command timed out");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn shell_group_isolation_never_signals_unrelated_process_group() {
        let dir = tempfile::tempdir().unwrap();
        // Launch sleep directly: killing the test fixture must not leave
        // its own child orphaned if an interactive shell chose not to exec.
        let mut unrelated = Command::new("/bin/sleep");
        unrelated
            .arg("4")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .kill_on_drop(true);
        let mut stranger = unrelated.spawn().unwrap();
        let result = run_approved_shell("printf isolated".into(), dir.path().to_path_buf())
            .await
            .unwrap();
        assert_eq!(result["stdout"], "isolated");
        assert!(
            stranger.try_wait().unwrap().is_none(),
            "unrelated process group was killed by shell cleanup"
        );
        stranger.start_kill().unwrap();
        stranger.wait().await.unwrap();
    }

    #[tokio::test]
    async fn bash_denied_before_execution() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("must-not-exist");
        let mut policies = HashMap::new();
        policies.insert("bash__run".into(), Policy::Disable);
        let reg = ToolRegistry::new(
            vec![root.path().canonicalize().unwrap()],
            ApprovalGate::new(policies),
        );
        let _ = reg.invoke(ToolCall {name:"bash__run".into(), arguments:json!({"cwd":root.path(),"command":format!("touch {}", marker.display())})}).await;
        assert!(!marker.exists());
    }

    #[test]
    fn does_not_grant_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        let reg = ToolRegistry::new(
            vec![root.path().canonicalize().unwrap()],
            ApprovalGate::new(HashMap::new()),
        );
        assert!(reg.allowed_path(root.path().parent().unwrap()).is_err());
    }
}
