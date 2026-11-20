use std::{collections::HashMap, fs::{self, OpenOptions}, io::Write, path::PathBuf};
use serde::{Deserialize, Serialize};
use crate::tools::approvals::Policy;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentSettings {
    pub allowed_roots: Vec<String>,
    pub policies: HashMap<String, Policy>,
}

fn file_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Home directory unavailable")?;
    Ok(home.join("Library/Application Support/com.gavindu.securityagent.desktop/settings.json"))
}

impl AgentSettings {
    pub fn load() -> Result<Self, String> {
        let path = file_path()?;
        match fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("Invalid settings.json: {e}")),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("Cannot load settings.json: {e}")),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let path = file_path()?;
        fs::create_dir_all(path.parent().ok_or("Invalid settings path")?).map_err(|e| e.to_string())?;
        let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<(), String> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)] {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp).map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&tmp, &path).map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() { let _ = fs::remove_file(tmp); }
        result
    }
}
