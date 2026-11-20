use crate::tools::approvals::ApprovalGate;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::process::Command;

const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_SHELL_OUTPUT: usize = 8 * 1024;

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
                let mut process = Command::new("/bin/sh");
                process
                    .arg("-lc")
                    .arg(&input.command)
                    .current_dir(directory)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin")
                    .kill_on_drop(true);
                let result = tokio::time::timeout(Duration::from_secs(15), process.output())
                    .await
                    .map_err(|_| "Command timed out".to_string())?
                    .map_err(|e| format!("Process launch failed: {e}"))?;
                Ok(json!({
                    "exit_code": result.status.code(),
                    "stdout": String::from_utf8_lossy(&result.stdout[..result.stdout.len().min(MAX_SHELL_OUTPUT)]),
                    "stderr": String::from_utf8_lossy(&result.stderr[..result.stderr.len().min(MAX_SHELL_OUTPUT)]),
                    "output_truncated": result.stdout.len() > MAX_SHELL_OUTPUT || result.stderr.len() > MAX_SHELL_OUTPUT
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
