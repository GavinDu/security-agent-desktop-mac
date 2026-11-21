use crate::tools::approvals::Policy;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::{
    ffi::CString,
    os::fd::{AsRawFd, FromRawFd},
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
};

const MAX_SETTINGS_BYTES: u64 = 256 * 1024;

/// Open and pin the final application support directory, not a pathname leaf
/// that can be swapped after a metadata preflight. Earlier ancestors remain
/// outside this narrow protection and need separate privileged OS policy.
#[cfg(unix)]
fn checked_settings_directory(path: &Path) -> std::io::Result<File> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: an open() success transfers ownership of a new descriptor.
    let directory = unsafe { File::from_raw_fd(fd) };
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    }
    Ok(directory)
}

#[cfg(unix)]
fn settings_leaf(path: &Path) -> Result<CString, String> {
    let leaf = path.file_name().ok_or("Invalid settings filename")?;
    CString::new(leaf.as_bytes()).map_err(|_| "Invalid settings filename".into())
}

#[cfg(unix)]
fn open_settings_at(
    directory: &File,
    leaf: &CString,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> std::io::Result<File> {
    let fd = unsafe { libc::openat(directory.as_raw_fd(), leaf.as_ptr(), flags, mode as libc::c_uint) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a successful openat returns a new uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
}

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
        #[cfg(unix)]
        let file = {
            let parent = path.parent().ok_or("Invalid settings directory")?;
            let directory = match checked_settings_directory(parent) {
                Ok(directory) => directory,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Self::default());
                }
                Err(_) => return Err("Cannot safely open settings directory".into()),
            };
            let leaf = settings_leaf(path)?;
            match open_settings_at(
                &directory,
                &leaf,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                0,
            ) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Self::default());
                }
                Err(_) => return Err("Cannot open settings.json safely".into()),
            }
        };

        #[cfg(not(unix))]
        let mut file = {
            let mut opts = OpenOptions::new();
            opts.read(true);
            match opts.open(path) {
                Ok(file) => file,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    return Ok(Self::default());
                }
                Err(_) => return Err("Cannot open settings.json safely".into()),
            }
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
            if metadata.permissions().mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
            {
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
        #[cfg(unix)]
        {
            let parent = path.parent().ok_or("Invalid settings directory")?;
            let directory = checked_settings_directory(parent)
                .map_err(|_| "Cannot safely open settings directory")?;
            let leaf = settings_leaf(path)?;
            let temp = CString::new(format!(".settings-{}.tmp", uuid::Uuid::new_v4()))
                .map_err(|_| "Invalid temporary settings filename")?;
            let result = (|| -> Result<(), String> {
                let mut file = open_settings_at(
                    &directory,
                    &temp,
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
                .map_err(|_| "Cannot create temporary settings file")?;
                file.write_all(&bytes)
                    .map_err(|_| "Cannot write settings.json")?;
                file.sync_all().map_err(|_| "Cannot sync settings.json")?;
                if unsafe {
                    libc::renameat(
                        directory.as_raw_fd(),
                        temp.as_ptr(),
                        directory.as_raw_fd(),
                        leaf.as_ptr(),
                    )
                } != 0
                {
                    return Err("Cannot replace settings.json".into());
                }
                Ok(())
            })();
            if result.is_err() {
                // Remove only this process's uniquely named temporary leaf,
                // relative to the same owned directory. Never unlink the
                // committed settings leaf, a lock, or a substituted pathname.
                unsafe { libc::unlinkat(directory.as_raw_fd(), temp.as_ptr(), 0) };
            }
            return result;
        }

        #[cfg(not(unix))]
        {
            let tmp = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
            let result = (|| -> Result<(), String> {
                let mut file = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&tmp)
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

    #[cfg(unix)]
    #[test]
    fn settings_loader_rejects_fifo_without_blocking() {
        use std::{ffi::CString, os::unix::ffi::OsStrExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("settings.json");
        let c_path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: CString owns a valid NUL-terminated path for this syscall.
        assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
        // Without O_NONBLOCK a read-only open hangs before fstat rejects FIFO.
        assert_eq!(
            AgentSettings::load_at(&path).unwrap_err(),
            "Unsafe or oversized settings.json"
        );
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

    #[cfg(unix)]
    #[test]
    fn load_and_save_refuse_symlinked_settings_directory_without_touching_target() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        fs::create_dir(&real).unwrap();
        let leaf = real.join("settings.json");
        AgentSettings::default().save_at(&leaf).unwrap();
        let before = fs::read(&leaf).unwrap();

        let alias = temp.path().join("app-support");
        std::os::unix::fs::symlink(&real, &alias).unwrap();
        let swapped = alias.join("settings.json");
        assert_eq!(
            AgentSettings::load_at(&swapped).unwrap_err(),
            "Cannot safely open settings directory"
        );
        let mut changed = AgentSettings::default();
        changed.policies.insert("bash__run".into(), Policy::Auto);
        assert_eq!(
            changed.save_at(&swapped).unwrap_err(),
            "Cannot safely open settings directory"
        );
        assert_eq!(fs::read(&leaf).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn settings_reject_group_writable_parent_before_read_or_write() {
        use std::os::unix::fs::PermissionsExt;
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("app-support");
        fs::create_dir(&parent).unwrap();
        let leaf = parent.join("settings.json");
        AgentSettings::default().save_at(&leaf).unwrap();
        let old = fs::read(&leaf).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            AgentSettings::load_at(&leaf).unwrap_err(),
            "Cannot safely open settings directory"
        );
        assert_eq!(
            AgentSettings::default().save_at(&leaf).unwrap_err(),
            "Cannot safely open settings directory"
        );
        assert_eq!(fs::read(&leaf).unwrap(), old);
    }

    #[cfg(unix)]
    #[test]
    fn pinned_parent_descriptor_keeps_atomic_write_out_of_swapped_symlink() {
        let temp = tempfile::tempdir().unwrap();
        let original = temp.path().join("original");
        let moved = temp.path().join("moved");
        let outside = temp.path().join("outside");
        fs::create_dir(&original).unwrap();
        fs::create_dir(&outside).unwrap();
        fs::write(outside.join("settings.json"), b"outside-sentinel").unwrap();

        let dir = checked_settings_directory(&original).unwrap();
        fs::rename(&original, &moved).unwrap();
        std::os::unix::fs::symlink(&outside, &original).unwrap();

        let leaf = CString::new("settings.json").unwrap();
        let temporary = CString::new(".settings-fixture.tmp").unwrap();
        let mut file = open_settings_at(
            &dir,
            &temporary,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .unwrap();
        file.write_all(b"safe-settings").unwrap();
        file.sync_all().unwrap();
        assert_eq!(
            unsafe {
                libc::renameat(
                    dir.as_raw_fd(),
                    temporary.as_ptr(),
                    dir.as_raw_fd(),
                    leaf.as_ptr(),
                )
            },
            0
        );
        assert_eq!(
            fs::read(moved.join("settings.json")).unwrap(),
            b"safe-settings"
        );
        assert_eq!(
            fs::read(outside.join("settings.json")).unwrap(),
            b"outside-sentinel"
        );
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
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            }
            // Test schema fail-closed, not merely an unsafe mode failure.
            assert!(AgentSettings::load_at(&path).is_err());
        }
    }
}
