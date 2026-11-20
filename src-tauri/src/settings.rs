use crate::tools::approvals::Policy;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

const MAX_SETTINGS_BYTES: u64 = 256 * 1024;

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
        let mut opts = OpenOptions::new();
        opts.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Reject a leaf symlink at the actual kernel open, rather than
            // checking its path before open (a check/use race).
            opts.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }

        let mut file = match opts.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(_) => return Err("Cannot open settings.json safely".into()),
        };
        let metadata = file
            .metadata()
            .map_err(|_| "Cannot inspect settings.json")?;
        if !metadata.is_file() || metadata.len() > MAX_SETTINGS_BYTES {
            return Err("Unsafe or oversized settings.json".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if metadata.permissions().mode() & 0o777 != 0o600 || metadata.nlink() != 1 {
                return Err("Unsafe settings.json file permissions or links".into());
            }
        }

        // Keep the same bound if a writer appends after the metadata check.
        let mut bytes = Vec::new();
        file.take(MAX_SETTINGS_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Cannot read settings.json")?;
        if bytes.len() as u64 > MAX_SETTINGS_BYTES {
            return Err("Oversized settings.json".into());
        }
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid settings.json: {e}"))
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_at(&file_path()?)
    }

    fn save_at(&self, path: &Path) -> Result<(), String> {
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| "Cannot encode settings.json")?;
        if bytes.len() as u64 > MAX_SETTINGS_BYTES {
            return Err("Settings exceed 256 KiB limit".into());
        }
        fs::create_dir_all(path.parent().ok_or("Invalid settings path")?)
            .map_err(|_| "Cannot create settings directory")?;
        let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| -> Result<(), String> {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts.open(&tmp)
                .map_err(|_| "Cannot create temporary settings file")?;
            file.write_all(&bytes)
                .map_err(|_| "Cannot write settings.json")?;
            file.sync_all().map_err(|_| "Cannot sync settings.json")?;
            fs::rename(&tmp, path).map_err(|_| "Cannot replace settings.json")?;
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
        first
            .policies
            .insert("filesystem__read_file".into(), Policy::Auto);
        first.save_at(&path).unwrap();
        let loaded = AgentSettings::load_at(&path).unwrap();
        assert_eq!(loaded.allowed_roots, first.allowed_roots);
        assert_eq!(loaded.policies.get("bash__run"), Some(&Policy::Ask));
        assert_eq!(
            loaded.policies.get("filesystem__read_file"),
            Some(&Policy::Auto)
        );

        let mut second = AgentSettings::default();
        second.policies.insert("bash__run".into(), Policy::Disable);
        second.save_at(&path).unwrap();
        let reloaded = AgentSettings::load_at(&path).unwrap();
        assert!(reloaded.allowed_roots.is_empty());
        assert_eq!(reloaded.policies.get("bash__run"), Some(&Policy::Disable));
        assert!(!reloaded.policies.contains_key("filesystem__read_file"));

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

    #[cfg(unix)]
    #[test]
    fn settings_loader_rejects_symlinks_hardlinks_and_public_file_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original.json");
        let leaf = dir.path().join("settings.json");
        fs::write(&original, b"{\"allowed_roots\":[],\"policies\":{}}").unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();

        symlink(&original, &leaf).unwrap();
        assert!(AgentSettings::load_at(&leaf).is_err());
        fs::remove_file(&leaf).unwrap();

        fs::hard_link(&original, &leaf).unwrap();
        assert!(AgentSettings::load_at(&leaf).is_err());
        fs::remove_file(&leaf).unwrap();

        fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(AgentSettings::load_at(&original).is_err());
        fs::set_permissions(&original, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(AgentSettings::load_at(&original).is_ok());
    }

    #[test]
    fn bounded_settings_load_and_save_reject_oversize_without_replacing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let original = AgentSettings::default();
        original.save_at(&path).unwrap();
        let before = fs::read(&path).unwrap();

        let mut huge = AgentSettings::default();
        huge.allowed_roots = vec!["x".repeat(MAX_SETTINGS_BYTES as usize + 1)];
        assert!(huge.save_at(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);

        fs::write(&path, vec![b' '; (MAX_SETTINGS_BYTES + 1) as usize]).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(AgentSettings::load_at(&path).is_err());
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
