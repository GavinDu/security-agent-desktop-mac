use crate::tools::approvals::{ApprovalGate, Policy};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::process::{ExitStatus, Stdio};
use std::{
    fs::File,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, OnceLock, RwLock,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::{Child, Command},
    sync::{
        oneshot, OwnedRwLockReadGuard, OwnedRwLockWriteGuard, OwnedSemaphorePermit,
        RwLock as AsyncRwLock, Semaphore,
    },
};

const MAX_FILE_BYTES: u64 = 64 * 1024;
// Fail fast before a request can monopolize a blocking filesystem worker.
const MAX_ADMITTED_FILE_READS: usize = 32;
// Metadata syscalls may block on network mounts even before read admission.
const MAX_ADMITTED_PATH_PREFLIGHTS: usize = 16;
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
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    pub name: String,
    #[serde(default)]
    pub arguments: Value,
}

pub struct ToolRegistry {
    roots: Arc<RwLock<Vec<crate::tools::pinned_read::GrantedRoot>>>,
    // Tokio's FIFO/write-preferring guard must be held through the complete
    // blocking FD read or the accepted native grant save/publication.
    root_admission: Arc<AsyncRwLock<()>>,
    read_slots: Arc<Semaphore>,
    path_preflight_slots: Arc<Semaphore>,
    // Private process-local monotonic grant generation, not a caller-supplied
    // revision token. Used to reject already-revoked completed read results.
    root_generation: AtomicU64,
    // A trusted Clear that cannot finish must not reopen old admissions.
    clear_pending: AtomicBool,
    gate: Arc<ApprovalGate>,
}

impl ToolRegistry {
    pub fn new(
        roots: Vec<crate::tools::pinned_read::GrantedRoot>,
        gate: Arc<ApprovalGate>,
    ) -> Self {
        Self {
            roots: Arc::new(RwLock::new(roots)),
            root_admission: Arc::new(AsyncRwLock::new(())),
            read_slots: Arc::new(Semaphore::new(MAX_ADMITTED_FILE_READS)),
            path_preflight_slots: Arc::new(Semaphore::new(MAX_ADMITTED_PATH_PREFLIGHTS)),
            root_generation: AtomicU64::new(0),
            clear_pending: AtomicBool::new(false),
            gate,
        }
    }

    pub fn is_known(tool: &str) -> bool {
        matches!(tool, "filesystem__read_file" | "bash__run")
    }

    pub fn canonical_roots(
        roots: &[String],
    ) -> Result<Vec<crate::tools::pinned_read::GrantedRoot>, String> {
        crate::tools::pinned_read::canonical_roots(roots)
    }

    /// Acquire the authoritative publication lock BEFORE calling the durable
    /// settings writer. If poisoned, the save callback never runs, avoiding
    /// a persisted grant set that the live registry cannot publish.
    ///
    /// No await point is permitted while holding this synchronous guard.
    /// Fair/cancellable waiting remains separately tracked under #166.
    pub(crate) fn commit_roots_transaction(
        &self,
        roots: Vec<crate::tools::pinned_read::GrantedRoot>,
        persist: impl FnOnce() -> Result<(), String>,
    ) -> Result<(), String> {
        let mut current = self
            .roots
            .write()
            .map_err(|_| "Directory permission registry unavailable".to_owned())?;
        // Never persist new roots if the private epoch cannot advance.
        // Holding the std writer excludes all other epoch mutations.
        if self.root_generation.load(Ordering::Relaxed) == u64::MAX {
            return Err("Directory permission generation exhausted".to_owned());
        }
        persist()?;
        *current = roots;
        self.root_generation.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    // Direct setters are restricted to deterministic low-level tests. All
    // production native changes enter through the fair accepted publication
    // gate in commit_serialized_roots.
    #[cfg(test)]
    fn set_roots(&self, roots: Vec<crate::tools::pinned_read::GrantedRoot>) -> Result<(), String> {
        self.commit_roots_transaction(roots, || Ok(()))
    }

    // Called only while the native root mutation revision guard is held.
    // Cancellation or a failed save leaves the process-local latch set.
    pub(crate) fn suspend_for_clear(&self) {
        self.clear_pending.store(true, Ordering::SeqCst);
    }

    // Only after successful durable empty-root publication, while both
    // native mutation and fair publication guards are still held.
    pub(crate) fn finish_clear(&self) {
        self.clear_pending.store(false, Ordering::SeqCst);
    }

    pub(crate) fn ensure_no_pending_clear(&self) -> Result<(), String> {
        if self.clear_pending.load(Ordering::SeqCst) {
            return Err("Directory permission revocation pending; retry Clear".to_owned());
        }
        Ok(())
    }

    /// Called after the admitted pinned worker releases its read permit and
    /// BEFORE the shared ToolRegistry returns a successful JSON result to
    /// either native IPC or authenticated HTTP. A later Clear/Grant invalidates
    /// the result even when the underlying FD read itself completed safely.
    fn ensure_current_file_result(&self, expected_generation: u64) -> Result<(), String> {
        self.ensure_no_pending_clear()?;
        if self.root_generation.load(Ordering::Acquire) != expected_generation {
            return Err("File read authorization changed".to_owned());
        }
        Ok(())
    }

    /// No new FD worker may overtake a queued trusted Clear/Grant. Capacity
    /// is acquired first with a fail-fast bound; both owned permits are moved
    /// into spawn_blocking so disconnect cannot release them before FD I/O.
    async fn admit_scoped_read(
        &self,
    ) -> Result<(OwnedSemaphorePermit, OwnedRwLockReadGuard<()>), String> {
        self.ensure_no_pending_clear()?;
        let slot = Arc::clone(&self.read_slots)
            .try_acquire_owned()
            .map_err(|_| "Approved file read capacity exceeded".to_owned())?;
        let admission = Arc::clone(&self.root_admission).read_owned().await;
        // Recheck after the await: the Clear may have timed out while this
        // reader was queued. Dropping both guards on denial is automatic.
        self.ensure_no_pending_clear()?;
        Ok((slot, admission))
    }

    /// Last cancellable phase before accepted native publication. Writer
    /// intent queues ahead of later Tokio read permits on this shared gate.
    pub(crate) async fn reserve_root_publication(&self) -> OwnedRwLockWriteGuard<()> {
        Arc::clone(&self.root_admission).write_owned().await
    }

    // The read lease spans grant selection, FD-relative traversal, and all
    // bytes read. A root revoke must acquire this lock's WRITE side, so an
    // acknowledged Clear cannot leave an older worker reading a stale grant.
    // Execute only from the blocking pool: never hold std::sync::RwLock across
    // an async await or do disk I/O on the Tokio executor.
    #[cfg(unix)]
    fn scoped_read_with_lease<T>(
        roots: &RwLock<Vec<crate::tools::pinned_read::GrantedRoot>>,
        path: &Path,
        read: impl FnOnce(&File, &Path) -> Result<T, String>,
    ) -> Result<T, String> {
        let grants = roots
            .read()
            .map_err(|_| "Directory permission registry unavailable".to_owned())?;
        for grant in grants.iter() {
            if let Ok(relative) = path.strip_prefix(grant.path()) {
                if relative.components().next().is_some() {
                    let pinned = grant.clone_directory()?;
                    // Keep the guard live until the read closure returns.
                    return read(&pinned, relative);
                }
            }
        }
        Err("Path outside granted roots".into())
    }

    // Do all filesystem metadata and path resolution on a blocking worker,
    // never on the Tokio executor. The admission try_read is deliberately
    // short-lived and rejects preflights while Clear/Grant is waiting.
    fn allowed_path_against(
        roots: &RwLock<Vec<crate::tools::pinned_read::GrantedRoot>>,
        root_admission: &AsyncRwLock<()>,
        requested: &Path,
    ) -> Result<PathBuf, String> {
        let resolved = requested
            .canonicalize()
            .map_err(|_| "Requested file path is inaccessible".to_string())?;
        let _preflight = root_admission
            .try_read()
            .map_err(|_| "Directory permission update pending".to_owned())?;
        let permitted = roots
            .read()
            .map_err(|_| "Directory permission registry unavailable".to_owned())?
            .iter()
            .any(|root| resolved.starts_with(root.path()));
        if !permitted {
            return Err("Path outside granted roots".into());
        }
        Ok(resolved)
    }

    // Retained only for deterministic sync authorization regression tests.
    #[cfg(test)]
    fn allowed_path(&self, requested: &Path) -> Result<PathBuf, String> {
        Self::allowed_path_against(&self.roots, &self.root_admission, requested)
    }

    // The slot is moved into the blocking closure, rather than owned by the
    // request future. A dropped caller cannot free capacity while its kernel
    // metadata syscall is still in progress. Bounded admission also avoids
    // launching unbounded tasks into Tokio's global blocking worker pool.
    async fn offload_path_check(
        &self,
        check: impl FnOnce() -> Result<PathBuf, String> + Send + 'static,
    ) -> Result<PathBuf, String> {
        let slot = Arc::clone(&self.path_preflight_slots)
            .try_acquire_owned()
            .map_err(|_| "Approved path check capacity exceeded".to_owned())?;
        tokio::task::spawn_blocking(move || {
            let _slot = slot;
            check()
        })
        .await
        .map_err(|_| "Approved path check task failed".to_owned())?
    }

    async fn allowed_path_for_tool(
        &self,
        requested: PathBuf,
        require_directory: bool,
    ) -> Result<PathBuf, String> {
        self.ensure_no_pending_clear()?;
        let roots = Arc::clone(&self.roots);
        let root_admission = Arc::clone(&self.root_admission);
        let resolved = self.offload_path_check(move || {
            let resolved = Self::allowed_path_against(&roots, &root_admission, &requested)?;
            // Directory metadata is also potentially blocking on slow mounts.
            if require_directory && !resolved.is_dir() {
                return Err("cwd must be a directory".into());
            }
            Ok(resolved)
        })
        .await?;
        self.ensure_no_pending_clear()?;
        Ok(resolved)
    }

    // Ask may wait 60 seconds. Recheck live grant and policy AFTER the wait
    // using a second independent bounded worker; do not hold an admission
    // permit or registry guard over interactive approval.
    async fn reauthorize_after_approval(&self, tool: &str, approved: &Path) -> Result<(), String> {
        if self.gate.policy(tool) == Policy::Disable {
            return Err("Tool disabled by policy".into());
        }
        let current = self
            .allowed_path_for_tool(approved.to_path_buf(), tool == "bash__run")
            .await?;
        if current != approved {
            return Err("Approved path changed during authorization".into());
        }
        if self.gate.policy(tool) == Policy::Disable {
            return Err("Tool disabled by policy".into());
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<Value> {
        // The same registry serves Tauri IPC and authenticated HTTP. Hide an
        // explicitly disabled capability from both discovery surfaces, using
        // the CURRENT live policy (not the last persisted snapshot).
        // The approval gate still enforces Disable at invocation time.
        vec![
            json!({"type":"function","function":{"name":"filesystem__read_file","description":"Read a UTF-8 file (64 KiB maximum) beneath a user-granted root.","parameters":{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"additionalProperties":false}}}),
            json!({"type":"function","function":{"name":"bash__run","description":"Run a shell command in a granted directory, with an interactive approval gate and 15-second timeout.","parameters":{"type":"object","properties":{"command":{"type":"string"},"cwd":{"type":"string"}},"required":["command","cwd"],"additionalProperties":false}}}),
        ]
        .into_iter()
        .filter(|tool| {
            let name = tool["function"]["name"].as_str().unwrap_or_default();
            self.gate.policy(name) != Policy::Disable
        })
        .collect()
    }

    pub async fn invoke(&self, call: ToolCall) -> Result<Value, String> {
        if !Self::is_known(&call.name) {
            return Err("Unknown tool".into());
        }
        match call.name.as_str() {
            "filesystem__read_file" => {
                let input: ReadInput = serde_json::from_value(call.arguments)
                    .map_err(|_| "Expected { path: string }".to_owned())?;
                let path = self
                    .allowed_path_for_tool(PathBuf::from(&input.path), false)
                    .await?;
                self.gate
                    .require("filesystem__read_file", &format!("Read {}", path.display()))
                    .await?;
                self.reauthorize_after_approval("filesystem__read_file", &path)
                    .await?;
                #[cfg(unix)]
                let (read_slot, read_gate) = self.admit_scoped_read().await?;
                // Once fair admission is held, no writer can publish until
                // the blocking worker releases it. Capture a trusted epoch.
                #[cfg(unix)]
                let read_generation = self.root_generation.load(Ordering::Acquire);
                // A separate caller may revoke roots between approval and
                // the blocking worker. Resolve the CURRENT pinned grant and
                // retain its read lease through the entire bounded read.
                #[cfg(unix)]
                let roots = Arc::clone(&self.roots);
                #[cfg(unix)]
                let read_path = path.clone();
                #[cfg(unix)]
                let text = tokio::task::spawn_blocking(move || {
                    // Owned guard and capacity remain held even if requester
                    // drops its JoinHandle before this FD read completes.
                    let _read_slot = read_slot;
                    let _read_gate = read_gate;
                    Self::scoped_read_with_lease(&roots, &read_path, |fd, relative| {
                        crate::tools::pinned_read::read_scoped_file(fd, relative)
                    })
                })
                .await
                .map_err(|_| "Approved file read task failed")??;
                #[cfg(unix)]
                self.ensure_current_file_result(read_generation)?;
                #[cfg(not(unix))]
                let text: String = return Err("Scoped reads require Unix".into());
                Ok(json!({ "path": path, "content": text }))
            }
            "bash__run" => {
                let input: RunInput = serde_json::from_value(call.arguments)
                    .map_err(|_| "Expected { command: string, cwd: string }".to_owned())?;
                if input.command.trim().is_empty() || input.command.len() > 4096 {
                    return Err("Invalid shell command length".into());
                }
                let directory = self
                    .allowed_path_for_tool(PathBuf::from(&input.cwd), true)
                    .await?;
                self.gate
                    .require(
                        "bash__run",
                        &format!("{} (cwd: {})", input.command, directory.display()),
                    )
                    .await?;
                self.reauthorize_after_approval("bash__run", &directory)
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
    #[test]
    fn poisoned_root_registry_fails_closed_without_panicking_or_saving() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("safe.txt");
        std::fs::write(&file, "must-not-read").unwrap();
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        );
        // Deliberately simulate a writer panic while its guard is held.
        // A poisoned write lock cannot be recovered as an authorization source.
        let poisoned = Arc::clone(&registry.roots);
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.write().unwrap();
            panic!("intentional test-only registry poisoning");
        })
        .join()
        .is_err());
        let expected = "Directory permission registry unavailable";
        assert_eq!(registry.allowed_path(&file).unwrap_err(), expected);
        assert_eq!(registry.set_roots(Vec::new()).unwrap_err(), expected);
        let mut persisted = false;
        let err = registry
            .commit_roots_transaction(Vec::new(), || {
                persisted = true;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(err, expected);
        assert!(!persisted, "poisoned state must fail before disk save");
        #[cfg(unix)]
        {
            let error = ToolRegistry::scoped_read_with_lease(
                &registry.roots,
                &file.canonicalize().unwrap(),
                crate::tools::pinned_read::read_scoped_file,
            )
            .unwrap_err();
            assert_eq!(error, expected);
        }
    }

    #[test]
    fn tool_call_envelope_requires_exact_fields_on_both_http_and_tauri_paths() {
        for (name, arguments) in [
            ("filesystem__read_file", json!({"path":"/safe/file.txt"})),
            ("bash__run", json!({"command":"echo ok","cwd":"/safe"})),
        ] {
            let valid = json!({"name":name,"arguments":arguments});
            let parsed: ToolCall = serde_json::from_value(valid.clone()).unwrap();
            assert_eq!(parsed.name, name);
            assert_eq!(parsed.arguments, arguments);

            for forbidden in ["approval", "admin", "token", "id", "type"] {
                let mut altered = valid.clone();
                altered
                    .as_object_mut()
                    .unwrap()
                    .insert(forbidden.to_owned(), json!(true));
                assert!(
                    serde_json::from_value::<ToolCall>(altered).is_err(),
                    "caller must not inject top-level {forbidden} into the tool contract"
                );
            }
        }

        // Missing tool identity fails at envelope parsing; an omitted
        // arguments payload remains the documented default Value::Null,
        // which each typed tool input rejects before any dispatch.
        assert!(serde_json::from_value::<ToolCall>(json!({"arguments":{}})).is_err());
        let omitted: ToolCall =
            serde_json::from_value(json!({"name":"filesystem__read_file"})).unwrap();
        assert!(omitted.arguments.is_null());
        assert!(serde_json::from_value::<ReadInput>(omitted.arguments).is_err());

        // Both underlying tool argument structs already independently
        // enforce additionalProperties:false (no approval-like fields).
        assert!(
            serde_json::from_value::<ReadInput>(json!({"path":"/safe","approval":true})).is_err()
        );
        assert!(serde_json::from_value::<RunInput>(
            json!({"command":"true","cwd":"/safe","admin":true})
        )
        .is_err());
    }

    #[tokio::test]
    async fn disabled_tools_are_hidden_and_remain_denied_at_invocation() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("visible.txt");
        std::fs::write(&path, "safe content").unwrap();
        let gate = ApprovalGate::new(HashMap::new());
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            gate.clone(),
        );
        let names = || {
            registry
                .list()
                .iter()
                .filter_map(|item| item["function"]["name"].as_str().map(str::to_owned))
                .collect::<Vec<_>>()
        };

        assert_eq!(names(), vec!["filesystem__read_file", "bash__run"]);
        gate.set_policy("filesystem__read_file", Policy::Disable);
        assert_eq!(names(), vec!["bash__run"]);
        let denied = registry
            .invoke(ToolCall {
                name: "filesystem__read_file".into(),
                arguments: json!({"path": path}),
            })
            .await
            .unwrap_err();
        assert_eq!(denied, "Tool disabled by policy");

        gate.set_policy("bash__run", Policy::Disable);
        assert!(names().is_empty());
        gate.set_policy("filesystem__read_file", Policy::Ask);
        assert_eq!(names(), vec!["filesystem__read_file"]);
        gate.set_policy("bash__run", Policy::Auto);
        assert_eq!(names(), vec!["filesystem__read_file", "bash__run"]);
    }

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
            ToolRegistry::canonical_roots(&[allowed.path().to_string_lossy().into_owned()])
                .unwrap(),
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

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn queued_root_writer_precedes_later_admitted_file_read() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("safe.txt");
        std::fs::write(&file, "old content").unwrap();
        // Match canonical /private/var paths on macOS native CI.
        let file = file.canonicalize().unwrap();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        ));
        let (first_slot, first_gate) = registry.admit_scoped_read().await.unwrap();
        let (writer_started_tx, writer_started_rx) = oneshot::channel();
        let writer_registry = Arc::clone(&registry);
        let mut writer = tokio::spawn(async move {
            writer_started_tx.send(()).unwrap();
            let _writer = writer_registry.reserve_root_publication().await;
            writer_registry
                .commit_roots_transaction(Vec::new(), || Ok(()))
                .unwrap();
        });
        writer_started_rx.await.unwrap();
        // The writer has entered its write_owned() wait before the next
        // reader is scheduled, so Tokio's fair lock must queue it behind.
        tokio::task::yield_now().await;
        let later_registry = Arc::clone(&registry);
        let later_file = file.clone();
        let mut later = tokio::spawn(async move {
            let (_slot, _read_gate) = later_registry.admit_scoped_read().await.unwrap();
            ToolRegistry::scoped_read_with_lease(
                &later_registry.roots,
                &later_file,
                crate::tools::pinned_read::read_scoped_file,
            )
        });
        assert!(
            tokio::time::timeout(Duration::from_millis(75), &mut writer)
                .await
                .is_err(),
            "the first admitted reader must hold up a subsequent writer"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(75), &mut later)
                .await
                .is_err(),
            "a late read must never overtake queued revocation"
        );
        assert_eq!(
            registry.allowed_path(&file).unwrap_err(),
            "Directory permission update pending"
        );
        drop(first_gate);
        drop(first_slot);
        writer.await.unwrap();
        assert_eq!(
            later.await.unwrap().unwrap_err(),
            "Path outside granted roots"
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn hundred_late_read_arrivals_cannot_overtake_root_revocation() {
        use std::{future::Future, task::Poll};

        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("safe.txt");
        std::fs::write(&file, "old content").unwrap();
        let file = file.canonicalize().unwrap();
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        );
        let (first_slot, first_gate) = registry.admit_scoped_read().await.unwrap();
        let mut writer = Box::pin(registry.reserve_root_publication());
        // Poll exactly once to establish FIFO writer intent without sleeps.
        std::future::poll_fn(|cx| {
            assert!(writer.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        let mut queued = Vec::new();
        let mut rejected = 0;
        for _ in 0..100 {
            let mut arrival = Box::pin(registry.admit_scoped_read());
            let waiting = std::future::poll_fn(|cx| {
                Poll::Ready(match arrival.as_mut().poll(cx) {
                    Poll::Pending => true,
                    Poll::Ready(Err(error)) => {
                        assert_eq!(error, "Approved file read capacity exceeded");
                        false
                    }
                    Poll::Ready(Ok(_)) => panic!("late reader overtook writer intent"),
                })
            })
            .await;
            if waiting {
                queued.push(arrival);
            } else {
                rejected += 1;
            }
        }
        assert_eq!(queued.len(), MAX_ADMITTED_FILE_READS - 1);
        assert_eq!(rejected, 100 - queued.len());
        assert_eq!(registry.read_slots.available_permits(), 0);
        drop(first_gate);
        drop(first_slot);

        let writer_guard = tokio::time::timeout(Duration::from_secs(2), writer)
            .await
            .unwrap();
        registry
            .commit_roots_transaction(Vec::new(), || Ok(()))
            .unwrap();
        drop(writer_guard);

        for arrival in queued {
            let (_slot, _guard) = tokio::time::timeout(Duration::from_secs(2), arrival)
                .await
                .unwrap()
                .unwrap();
            let denied = ToolRegistry::scoped_read_with_lease(
                &registry.roots,
                &file,
                crate::tools::pinned_read::read_scoped_file,
            )
            .unwrap_err();
            assert_eq!(denied, "Path outside granted roots");
        }
        assert_eq!(
            registry.read_slots.available_permits(),
            MAX_ADMITTED_FILE_READS
        );
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn completed_file_result_denied_after_root_clear_before_json_return() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("canary.txt");
        std::fs::write(&file, "SENSITIVE_FILE_CONTENT").unwrap();
        let file = file.canonicalize().unwrap();
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        );
        let (_slot, held_gate) = registry.admit_scoped_read().await.unwrap();
        let authorized_generation = registry.root_generation.load(Ordering::Acquire);
        // Use the same pinned FD-relative read path as the actual invoke.
        let content = ToolRegistry::scoped_read_with_lease(
            &registry.roots,
            &file,
            crate::tools::pinned_read::read_scoped_file,
        )
        .unwrap();
        assert_eq!(content, "SENSITIVE_FILE_CONTENT");
        registry
            .ensure_current_file_result(authorized_generation)
            .unwrap();

        // Once I/O is complete its read permit is released. A trusted Clear
        // can now publish before native/HTTP JSON delivery begins.
        drop(held_gate);
        registry
            .commit_roots_transaction(Vec::new(), || Ok(()))
            .unwrap();
        assert_eq!(
            registry
                .ensure_current_file_result(authorized_generation)
                .unwrap_err(),
            "File read authorization changed"
        );
        assert_eq!(
            ToolRegistry::scoped_read_with_lease(
                &registry.roots,
                &file,
                crate::tools::pinned_read::read_scoped_file
            )
            .unwrap_err(),
            "Path outside granted roots"
        );
    }

    #[test]
    fn root_generation_only_advances_after_successful_publication() {
        let registry = ToolRegistry::new(Vec::new(), ApprovalGate::new(HashMap::new()));
        let initial = registry.root_generation.load(Ordering::Acquire);
        assert_eq!(initial, 0);
        assert_eq!(
            registry
                .commit_roots_transaction(Vec::new(), || {
                    Err("secret filesystem path".to_owned())
                })
                .unwrap_err(),
            "secret filesystem path"
        );
        assert_eq!(registry.root_generation.load(Ordering::Acquire), initial);
        registry
            .commit_roots_transaction(Vec::new(), || Ok(()))
            .unwrap();
        registry
            .commit_roots_transaction(Vec::new(), || Ok(()))
            .unwrap();
        assert_eq!(
            registry.root_generation.load(Ordering::Acquire),
            initial + 2
        );
        registry.root_generation.store(u64::MAX, Ordering::Release);
        let mut persisted = false;
        assert_eq!(
            registry
                .commit_roots_transaction(Vec::new(), || {
                    persisted = true;
                    Ok(())
                })
                .unwrap_err(),
            "Directory permission generation exhausted"
        );
        assert!(!persisted, "overflow must fail before disk persistence");
    }

    #[tokio::test]
    async fn scoped_read_slots_bound_active_and_waiting_workers() {
        let registry = ToolRegistry::new(Vec::new(), ApprovalGate::new(HashMap::new()));
        let mut held = Vec::new();
        for _ in 0..MAX_ADMITTED_FILE_READS {
            held.push(registry.admit_scoped_read().await.unwrap());
        }
        assert_eq!(
            registry.admit_scoped_read().await.err().unwrap(),
            "Approved file read capacity exceeded"
        );
        held.pop();
        let next = registry.admit_scoped_read().await;
        assert!(next.is_ok(), "dropping a reader must reclaim capacity");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn async_path_preflight_preserves_grants_and_directory_type() {
        let root = tempfile::tempdir().unwrap();
        let document = root.path().join("allowed.txt");
        std::fs::write(&document, "safe").unwrap();
        let document = document.canonicalize().unwrap();
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        );
        assert_eq!(
            registry
                .allowed_path_for_tool(document.clone(), false)
                .await
                .unwrap(),
            document
        );
        assert_eq!(
            registry
                .allowed_path_for_tool(document.clone(), true)
                .await
                .unwrap_err(),
            "cwd must be a directory"
        );
        registry.set_roots(Vec::new()).unwrap();
        assert_eq!(
            registry
                .allowed_path_for_tool(document, false)
                .await
                .unwrap_err(),
            "Path outside granted roots"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocking_path_preflight_stays_bounded_after_request_cancellation() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Condvar, Mutex,
        };

        let registry = Arc::new(ToolRegistry::new(
            Vec::new(),
            ApprovalGate::new(HashMap::new()),
        ));
        let entered = Arc::new(AtomicUsize::new(0));
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let mut requests = Vec::new();

        for _ in 0..MAX_ADMITTED_PATH_PREFLIGHTS {
            let reg = Arc::clone(&registry);
            let entered = Arc::clone(&entered);
            let release = Arc::clone(&release);
            requests.push(tokio::spawn(async move {
                reg.offload_path_check(move || {
                    entered.fetch_add(1, AtomicOrdering::Release);
                    let (lock, ready) = &*release;
                    let mut permitted = lock.lock().unwrap();
                    while !*permitted {
                        let (next, timed) = ready
                            .wait_timeout(permitted, Duration::from_secs(10))
                            .unwrap();
                        permitted = next;
                        if timed.timed_out() && !*permitted {
                            return Err("Native path test fixture timed out".into());
                        }
                    }
                    Ok(PathBuf::from("/fixture-only"))
                })
                .await
            }));
        }

        // This timeout and yield execute on a *single-threaded Tokio
        // executor*. A direct blocking canonicalization path would prevent
        // the reactor from scheduling this test's progress.
        tokio::time::timeout(Duration::from_secs(7), async {
            while entered.load(AtomicOrdering::Acquire) != MAX_ADMITTED_PATH_PREFLIGHTS {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all bounded blocking preflight workers must start");

        assert_eq!(
            registry
                .offload_path_check(|| Ok(PathBuf::from("/rejected")))
                .await
                .unwrap_err(),
            "Approved path check capacity exceeded"
        );
        // Aborting one request must NOT free its worker's slot before its
        // underlying syscall would return.
        let canceled = requests.pop().unwrap();
        canceled.abort();
        let _ = canceled.await;
        assert_eq!(
            registry
                .offload_path_check(|| Ok(PathBuf::from("/still-rejected")))
                .await
                .unwrap_err(),
            "Approved path check capacity exceeded"
        );

        let (lock, ready) = &*release;
        *lock.lock().unwrap() = true;
        ready.notify_all();
        for request in requests {
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(5), request)
                    .await
                    .unwrap()
                    .unwrap()
                    .unwrap(),
                PathBuf::from("/fixture-only")
            );
        }
        // The canceled worker may still be releasing its owned slot.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                match registry
                    .offload_path_check(|| Ok(PathBuf::from("/reclaimed")))
                    .await
                {
                    Ok(path) => {
                        assert_eq!(path, PathBuf::from("/reclaimed"));
                        break;
                    }
                    Err(ref message) if message == "Approved path check capacity exceeded" => {
                        tokio::task::yield_now().await;
                    }
                    Err(other) => panic!("unexpected preflight error: {other}"),
                }
            }
        })
        .await
        .expect("finished metadata workers must release the bound");
    }

    #[cfg(unix)]
    #[test]
    fn acknowledged_root_revoke_waits_for_inflight_scoped_file_read() {
        use std::{sync::mpsc, thread};
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("safe.txt");
        std::fs::write(&file, "approved-content").unwrap();
        // macOS often resolves temporary /var paths to /private/var; use
        // the same canonical pathname the real tool would authorize.
        let file = file.canonicalize().unwrap();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        ));
        let roots = Arc::clone(&registry.roots);
        let read_path = file.clone();
        let (reading_tx, reading_rx) = mpsc::channel();
        let (continue_tx, continue_rx) = mpsc::channel();
        let reader = thread::spawn(move || {
            ToolRegistry::scoped_read_with_lease(&roots, &read_path, |fd, relative| {
                reading_tx.send(()).unwrap();
                // A read that already acquired the authoritative lease may
                // finish before Clear acknowledges, never AFTER it returns.
                continue_rx
                    .recv_timeout(Duration::from_secs(3))
                    .map_err(|_| "Test read lease fixture timed out".to_owned())?;
                crate::tools::pinned_read::read_scoped_file(fd, relative)
            })
        });
        reading_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(
            matches!(
                registry.roots.try_write(),
                Err(std::sync::TryLockError::WouldBlock)
            ),
            "an in-flight scoped read must retain the actual registry read lock"
        );

        let (writer_started_tx, writer_started_rx) = mpsc::channel();
        let (revoked_tx, revoked_rx) = mpsc::channel();
        let writer_registry = Arc::clone(&registry);
        let writer = thread::spawn(move || {
            writer_started_tx.send(()).unwrap();
            writer_registry.set_roots(Vec::new()).unwrap();
            revoked_tx.send(()).unwrap();
        });
        writer_started_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
        assert!(
            revoked_rx.recv_timeout(Duration::from_millis(80)).is_err(),
            "a root revoke cannot report success before the old read releases its lease"
        );
        continue_tx.send(()).unwrap();
        assert_eq!(reader.join().unwrap().unwrap(), "approved-content");
        revoked_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        writer.join().unwrap();

        // A later invocation cannot clone or use the former directory FD.
        let denied = ToolRegistry::scoped_read_with_lease(
            &registry.roots,
            &file,
            crate::tools::pinned_read::read_scoped_file,
        )
        .unwrap_err();
        assert_eq!(denied, "Path outside granted roots");
    }

    #[cfg(unix)]
    #[test]
    fn revoked_root_precedes_any_queued_scoped_read() {
        let root = tempfile::tempdir().unwrap();
        let file = root.path().join("safe.txt");
        std::fs::write(&file, "never reauthorized").unwrap();
        let file = file.canonicalize().unwrap();
        let registry = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        );
        registry.set_roots(Vec::new()).unwrap();
        let error = ToolRegistry::scoped_read_with_lease(
            &registry.roots,
            &file,
            |_fd, _rel| -> Result<String, String> {
                panic!("revoked file read must fail before any openat operation")
            },
        )
        .unwrap_err();
        assert_eq!(error, "Path outside granted roots");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn parent_symlink_swap_during_approval_is_denied() {
        let temp = tempfile::tempdir().unwrap();
        let grant = temp.path().join("grant");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&grant).unwrap();
        std::fs::create_dir(&outside).unwrap();
        let child = grant.join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::write(child.join("file.txt"), "original").unwrap();
        std::fs::write(outside.join("file.txt"), "outside-secret").unwrap();
        let mut policies = HashMap::new();
        policies.insert("filesystem__read_file".into(), Policy::Ask);
        let gate = ApprovalGate::new(policies);
        let mut events = gate.subscribe();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[grant.to_string_lossy().into_owned()]).unwrap(),
            gate.clone(),
        ));
        let requested = child.join("file.txt");
        let request = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .invoke(ToolCall {
                        name: "filesystem__read_file".into(),
                        arguments: json!({"path": requested}),
                    })
                    .await
            }
        });
        let approval = events.recv().await.unwrap();
        std::fs::rename(&child, grant.join("original-child")).unwrap();
        std::os::unix::fs::symlink(&outside, &child).unwrap();
        gate.resolve(uuid::Uuid::parse_str(&approval.id).unwrap(), true)
            .await;
        let result = request.await.unwrap();
        assert!(
            result.is_err(),
            "parent symlink swap must not escape pinned grant"
        );
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
        // the SAME PGID holding stdout/stderr open without writing to them.
        // The inner shell ignores TERM and writes a file heartbeat, so a
        // broken stdout pipe cannot be mistaken for successful group KILL.
        let command = format!(
            "sh -c 'trap \"\" TERM; while :; do printf x >> \"{}\"; sleep 0.02; done' & exit 0",
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
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(policies),
        );
        let _ = reg.invoke(ToolCall {name:"bash__run".into(), arguments:json!({"cwd":root.path(),"command":format!("touch {}", marker.display())})}).await;
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn revoked_root_after_approval_request_cannot_launch_bash() {
        let root = tempfile::tempdir().unwrap();
        let marker = root.path().join("revoked-must-not-run");
        let mut policies = HashMap::new();
        policies.insert("bash__run".into(), Policy::Ask);
        let gate = ApprovalGate::new(policies);
        let mut listener = gate.subscribe();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            gate.clone(),
        ));
        let command = format!("touch {}", marker.display());
        let cwd = root.path().to_path_buf();
        let pending = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .invoke(ToolCall {
                        name: "bash__run".into(),
                        arguments: json!({"cwd":cwd, "command":command}),
                    })
                    .await
            }
        });
        let event = tokio::time::timeout(Duration::from_secs(3), listener.recv())
            .await
            .unwrap()
            .unwrap();
        registry.set_roots(Vec::new()).unwrap();
        assert!(
            gate.resolve(uuid::Uuid::parse_str(&event.id).unwrap(), true)
                .await
        );
        assert!(pending.await.unwrap().is_err());
        assert!(!marker.exists());
    }

    #[tokio::test]
    async fn disabling_file_tool_during_approval_denies_stale_approval() {
        let root = tempfile::tempdir().unwrap();
        let document = root.path().join("allowed.txt");
        std::fs::write(&document, b"old file").unwrap();
        let mut policies = HashMap::new();
        policies.insert("filesystem__read_file".into(), Policy::Ask);
        let gate = ApprovalGate::new(policies);
        let mut listener = gate.subscribe();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            gate.clone(),
        ));
        let pending = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .invoke(ToolCall {
                        name: "filesystem__read_file".into(),
                        arguments: json!({"path":document}),
                    })
                    .await
            }
        });
        let event = tokio::time::timeout(Duration::from_secs(3), listener.recv())
            .await
            .unwrap()
            .unwrap();
        gate.set_policy("filesystem__read_file", Policy::Disable);
        assert!(
            gate.resolve(uuid::Uuid::parse_str(&event.id).unwrap(), true)
                .await
        );
        let outcome = pending.await.unwrap().unwrap_err();
        assert_eq!(outcome, "Tool disabled by policy");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn replacing_approved_file_name_during_approval_is_denied() {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("approved.txt");
        let replacement = root.path().join("replacement.txt");
        std::fs::write(&original, b"original").unwrap();
        std::fs::write(&replacement, b"different").unwrap();
        let mut policies = HashMap::new();
        policies.insert("filesystem__read_file".into(), Policy::Ask);
        let gate = ApprovalGate::new(policies);
        let mut listener = gate.subscribe();
        let registry = Arc::new(ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            gate.clone(),
        ));
        let name = original.clone();
        let pending = tokio::spawn({
            let registry = registry.clone();
            async move {
                registry
                    .invoke(ToolCall {
                        name: "filesystem__read_file".into(),
                        arguments: json!({"path":name}),
                    })
                    .await
            }
        });
        let event = tokio::time::timeout(Duration::from_secs(3), listener.recv())
            .await
            .unwrap()
            .unwrap();
        std::fs::rename(&original, root.path().join("moved.txt")).unwrap();
        std::os::unix::fs::symlink(&replacement, &original).unwrap();
        assert!(
            gate.resolve(uuid::Uuid::parse_str(&event.id).unwrap(), true)
                .await
        );
        let outcome = pending.await.unwrap().unwrap_err();
        assert_eq!(outcome, "Approved path changed during authorization");
    }

    #[test]
    fn file_authorization_errors_do_not_echo_private_paths() {
        let profile = tempfile::tempdir().unwrap();
        let private_marker = "PRIVATE_PROFILE_CANARY_17FBA2";
        let private = profile.path().join(private_marker);
        let absent = private.join("missing");
        let rejected_root = ToolRegistry::canonical_roots(&[absent.to_string_lossy().into_owned()])
            .err()
            .expect("missing root must be denied");
        assert!(!rejected_root.contains(private_marker));
        assert_eq!(rejected_root, "Invalid granted root");

        let real_file = profile.path().join(private_marker);
        std::fs::write(&real_file, b"not a directory").unwrap();
        let invalid_dir =
            ToolRegistry::canonical_roots(&[real_file.to_string_lossy().into_owned()])
                .err()
                .expect("file cannot become a directory grant");
        assert!(!invalid_dir.contains(private_marker));
        assert_eq!(invalid_dir, "Granted root is not a directory");

        let gate = ApprovalGate::new(HashMap::new());
        let reg = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[profile.path().to_string_lossy().into_owned()])
                .unwrap(),
            gate,
        );
        let inaccessible = reg
            .allowed_path(&real_file.join("missing"))
            .expect_err("nonexistent file must fail closed");
        assert!(!inaccessible.contains(private_marker));
        assert_eq!(inaccessible, "Requested file path is inaccessible");

        let outside = tempfile::tempdir().unwrap();
        let denied = reg
            .allowed_path(outside.path())
            .expect_err("ungranted directory denied");
        assert_eq!(denied, "Path outside granted roots");
        assert_eq!(
            reg.allowed_path(&real_file).unwrap(),
            real_file.canonicalize().unwrap(),
        );
    }

    #[test]
    fn does_not_grant_parent_directory() {
        let root = tempfile::tempdir().unwrap();
        let reg = ToolRegistry::new(
            ToolRegistry::canonical_roots(&[root.path().to_string_lossy().into_owned()]).unwrap(),
            ApprovalGate::new(HashMap::new()),
        );
        assert!(reg.allowed_path(root.path().parent().unwrap()).is_err());
    }
}
