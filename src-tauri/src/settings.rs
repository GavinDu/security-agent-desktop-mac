use crate::tools::approvals::Policy;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

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
        Self::load_at(&file_path()?)
    }

    fn load_at(path: &Path) -> Result<Self, String> {
        match fs::read(path) {
            Ok(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| format!("Invalid settings.json: {e}"))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(format!("Cannot load settings.json: {e}")),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_at(&file_path()?)
    }

    fn save_at(&self, path: &Path) -> Result<(), String> {
        fs::create_dir_all(path.parent().ok_or("Invalid settings path")?)
            .map_err(|e| e.to_string())?;
        let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<(), String> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp).map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            fs::rename(&tmp, path).map_err(|e| e.to_string())?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(tmp);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_starts_with_no_permissions() {
        let dir = tempfile::tempdir().unwrap();
        let settings = AgentSettings::load_at(&dir.path().join("missing.json")).unwrap();
        assert!(settings.allowed_roots.is_empty());
        assert!(settings.policies.is_empty());
    }

    #[test]
    fn atomically_saves_and_reloads_restrictive_settings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("settings.json");
        let mut first = AgentSettings::default();
        first.allowed_roots = vec!["/Users/local/Documents".into()];
        first.policies.insert("bash__run".into(), Policy::Ask);
        first.save_at(&path).unwrap();
        let loaded = AgentSettings::load_at(&path).unwrap();
        assert_eq!(loaded.allowed_roots, first.allowed_roots);
        assert_eq!(loaded.policies.get("bash__run"), Some(&Policy::Ask));

        let mut second = AgentSettings::default();
        second.policies.insert("bash__run".into(), Policy::Disable);
        second.save_at(&path).unwrap();
        let reloaded = AgentSettings::load_at(&path).unwrap();
        assert!(reloaded.allowed_roots.is_empty());
        assert_eq!(reloaded.policies.get("bash__run"), Some(&Policy::Disable));

        let files: Vec<_> = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(files, vec![std::ffi::OsString::from("settings.json")]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn malformed_or_unknown_json_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        for text in [
            "{",
            r#"{"allowed_roots":[],"policies":{},"unknown_setting":true}"#,
            r#"{"allowed_roots":[],"policies":{"bash__run":"permit_all"}}"#,
        ] {
            fs::write(&path, text).unwrap();
            assert!(AgentSettings::load_at(&path).is_err());
        }
    }
}
