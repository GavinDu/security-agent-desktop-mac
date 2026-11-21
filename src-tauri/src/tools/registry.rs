use crate::tools::approvals::ApprovalGate;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::process::Stdio;
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_SHELL_OUTPUT: usize = 8 * 1024;

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
            let path =
                std::fs::canonicalize(root).map_err(|_| "Invalid granted root".to_string())?;
            if !path.is_dir() {
                return Err("Granted root is not a directory".into());
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
            .map_err(|_| "Requested file path is inaccessible".to_string())?;
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
                let mut process = Command::new("/bin/sh");
                process
                    .arg("-lc")
                    .arg(&input.command)
                    .current_dir(directory)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .kill_on_drop(true);
                let mut child = process
                    .spawn()
                    .map_err(|_| "Cannot launch approved command")?;
                let stdout = child.stdout.take().ok_or("Cannot capture command stdout")?;
                let stderr = child.stderr.take().ok_or("Cannot capture command stderr")?;
                // A timeout drops the readers and child; kill_on_drop covers
                // the direct shell. Process-group cleanup is tracked
                // separately in #35, not claimed by this output bound.
                let (stdout, stderr, status) =
                    tokio::time::timeout(Duration::from_secs(15), async {
                        tokio::try_join!(
                            read_bounded_output(stdout),
                            read_bounded_output(stderr),
                            child.wait()
                        )
                    })
                    .await
                    .map_err(|_| "Command timed out".to_string())?
                    .map_err(|_| "Command execution or output capture failed")?;
                Ok(json!({
                    "exit_code": status.code(),
                    "stdout": String::from_utf8_lossy(&stdout.0),
                    "stderr": String::from_utf8_lossy(&stderr.0),
                    "output_truncated": stdout.1 || stderr.1
                }))
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
    fn file_authorization_errors_do_not_echo_private_paths() {
        let profile = tempfile::tempdir().unwrap();
        let private_marker = "PRIVATE_PROFILE_CANARY_17FBA2";
        let private = profile.path().join(private_marker);
        let absent = private.join("missing");
        let rejected_root = ToolRegistry::canonical_roots(&[absent.to_string_lossy().into_owned()])
            .expect_err("missing root must be denied");
        assert!(!rejected_root.contains(private_marker));
        assert_eq!(rejected_root, "Invalid granted root");

        let real_file = profile.path().join(private_marker);
        std::fs::write(&real_file, b"not a directory").unwrap();
        let invalid_dir =
            ToolRegistry::canonical_roots(&[real_file.to_string_lossy().into_owned()])
                .expect_err("file cannot become a directory grant");
        assert!(!invalid_dir.contains(private_marker));
        assert_eq!(invalid_dir, "Granted root is not a directory");

        let gate = ApprovalGate::new(HashMap::new());
        let reg = ToolRegistry::new(vec![profile.path().canonicalize().unwrap()], gate);
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
            vec![root.path().canonicalize().unwrap()],
            ApprovalGate::new(HashMap::new()),
        );
        assert!(reg.allowed_path(root.path().parent().unwrap()).is_err());
    }
}
