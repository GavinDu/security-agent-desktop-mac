//! Staged per-account settings storage. The trusted account manager must
//! supply the UUID; no IPC/HTTP caller may select a filesystem account.
use super::{checked_settings_directory, open_settings_at, AgentSettings, MAX_SETTINGS_BYTES};
use std::{
    ffi::{CStr, CString},
    fs::File,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
use uuid::Uuid;

pub(super) struct AccountSettingsDirectory {
    directory: File,
}

pub(super) fn private_child(parent: &File, name: &CStr, create: bool) -> io::Result<File> {
    if create {
        // SAFETY: parent owns an open directory and name is a fixed CString.
        let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
        if result != 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::AlreadyExists {
                return Err(error);
            }
        }
    }
    // The original pinned parent remains the lookup anchor, even if a
    // pathname is swapped. Never chmod a preexisting untrusted directory.
    let name = name.to_owned();
    let child = open_settings_at(
        parent,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )?;
    let meta = child.metadata()?;
    if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o7777 != 0o700 {
        return Err(io::Error::from(io::ErrorKind::PermissionDenied));
    }
    Ok(child)
}

impl AccountSettingsDirectory {
    /// No global settings fallback. An absent account is distinct from an
    /// inaccessible account; only the trusted host may create a new one.
    pub(super) fn open(
        app_support: &Path,
        account: Uuid,
        create: bool,
    ) -> Result<Option<Self>, String> {
        if account.is_nil() {
            return Err("Invalid settings account".into());
        }
        let base = checked_settings_directory(app_support)
            .map_err(|_| "Account settings base unavailable")?;
        let root = CString::new("accounts-v1").expect("fixed name");
        let leaf = CString::new(account.hyphenated().to_string())
            .map_err(|_| "Invalid settings account")?;
        let root = match private_child(&base, &root, create) {
            Ok(root) => root,
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err("Account settings directory unavailable".into()),
        };
        Self::open_under(&root, &leaf, create)
    }

    pub(super) fn open_under(
        root: &File,
        leaf: &CStr,
        create: bool,
    ) -> Result<Option<Self>, String> {
        match private_child(root, leaf, create) {
            Ok(directory) => Ok(Some(Self { directory })),
            Err(error) if !create && error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err("Account settings directory unavailable".into()),
        }
    }

    /// Enrollment must persist the fresh settings leaf before publishing
    /// the account identity in the parent manifest.
    pub(super) fn sync_directory(&self) -> Result<(), String> {
        self.directory.sync_all().map_err(|_| "Account directory sync failed".into())
    }

    pub(super) fn load(&self) -> Result<AgentSettings, String> {
        let leaf = CString::new("settings.json").expect("fixed name");
        let file = match open_settings_at(
            &self.directory,
            &leaf,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(AgentSettings::default());
            }
            Err(_) => return Err("Account settings file unavailable".into()),
        };
        let meta = file
            .metadata()
            .map_err(|_| "Account settings file unavailable")?;
        if !meta.is_file()
            || meta.uid() != unsafe { libc::geteuid() }
            || meta.mode() & 0o7777 != 0o600
            || meta.nlink() != 1
            || meta.len() > MAX_SETTINGS_BYTES
        {
            return Err("Unsafe account settings file".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_SETTINGS_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| "Account settings read failed")?;
        if bytes.len() as u64 > MAX_SETTINGS_BYTES {
            return Err("Unsafe account settings file".into());
        }
        let settings: AgentSettings =
            serde_json::from_slice(&bytes).map_err(|_| "Invalid account settings")?;
        if !settings.only_known_tool_policies() {
            return Err("Invalid account settings".into());
        }
        Ok(settings)
    }

    pub(super) fn save(&self, settings: &AgentSettings) -> Result<(), String> {
        if !settings.only_known_tool_policies() {
            return Err("Invalid account settings".into());
        }
        let bytes = serde_json::to_vec_pretty(settings).map_err(|_| "Invalid account settings")?;
        if bytes.len() as u64 > MAX_SETTINGS_BYTES {
            return Err("Unsafe account settings file".into());
        }
        let leaf = CString::new("settings.json").expect("fixed name");
        let temp = CString::new(format!(".settings-{}.tmp", Uuid::new_v4()))
            .map_err(|_| "Account settings write failed")?;
        // Create-exclusive ownership is established before cleanup is allowed.
        let mut file = open_settings_at(
            &self.directory,
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|_| "Account settings write failed")?;
        let result = (|| {
            file.write_all(&bytes)
                .map_err(|_| "Account settings write failed")?;
            file.sync_all()
                .map_err(|_| "Account settings sync failed")?;
            // SAFETY: both leaves are fixed, relative to the same pinned
            // directory. Rename replaces the leaf, never follows a symlink.
            if unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    temp.as_ptr(),
                    self.directory.as_raw_fd(),
                    leaf.as_ptr(),
                )
            } != 0
            {
                return Err("Account settings replace failed");
            }
            Ok(())
        })();
        if result.is_err() {
            // Best effort only; never unlink a committed settings leaf.
            unsafe { libc::unlinkat(self.directory.as_raw_fd(), temp.as_ptr(), 0) };
        }
        result.map_err(str::to_owned)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::approvals::Policy;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    fn directory(base: &Path, account: Uuid) -> AccountSettingsDirectory {
        AccountSettingsDirectory::open(base, account, true)
            .unwrap()
            .unwrap()
    }

    fn path(base: &Path, account: Uuid) -> std::path::PathBuf {
        base.join("accounts-v1").join(account.to_string())
    }

    #[test]
    fn separate_accounts_never_inherit_legacy_or_other_account_settings() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        fs::write(base.join("settings.json"), b"legacy authority").unwrap();
        assert!(AccountSettingsDirectory::open(base, a, false)
            .unwrap()
            .is_none());
        let a_dir = directory(base, a);
        let b_dir = directory(base, b);
        let mut settings = AgentSettings::default();
        settings.allowed_roots.push("/fixture/a".into());
        settings
            .policies
            .insert("bash__run".into(), Policy::Disable);
        a_dir.save(&settings).unwrap();
        let read = a_dir.load().unwrap();
        assert_eq!(read.allowed_roots, vec!["/fixture/a"]);
        assert_eq!(read.policies.get("bash__run"), Some(&Policy::Disable));
        assert!(b_dir.load().unwrap().allowed_roots.is_empty());
        assert!(b_dir.load().unwrap().policies.is_empty());
        assert_eq!(
            fs::read(base.join("settings.json")).unwrap(),
            b"legacy authority"
        );
    }

    #[test]
    fn unsafe_directories_and_symlinks_never_open() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let a = Uuid::new_v4();
        let _dir = directory(base, a);
        let account = path(base, a);
        fs::set_permissions(&account, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(AccountSettingsDirectory::open(base, a, false).is_err());
        fs::set_permissions(&account, fs::Permissions::from_mode(0o700)).unwrap();
        let b = Uuid::new_v4();
        symlink(&account, path(base, b)).unwrap();
        assert!(AccountSettingsDirectory::open(base, b, true).is_err());
        assert!(AccountSettingsDirectory::open(base, Uuid::nil(), true).is_err());
    }

    #[test]
    fn unsafe_leaf_and_invalid_json_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let a = Uuid::new_v4();
        let dir = directory(base, a);
        let file = path(base, a).join("settings.json");
        let other = base.join("other");
        fs::write(&other, b"{}").unwrap();
        fs::set_permissions(&other, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&other, &file).unwrap();
        assert!(dir.load().is_err());
        fs::remove_file(&file).unwrap();
        fs::hard_link(&other, &file).unwrap();
        assert!(dir.load().is_err());
        fs::remove_file(&file).unwrap();
        for bytes in [
            b"{\"secret\":\"canary\"}".to_vec(),
            b"{\"policies\":{\"future__tool\":\"auto\"}}".to_vec(),
            vec![b'x'; MAX_SETTINGS_BYTES as usize + 1],
        ] {
            fs::write(&file, bytes).unwrap();
            fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
            assert!(dir.load().is_err());
        }
        dir.save(&AgentSettings::default()).unwrap();
        assert!(dir.load().unwrap().allowed_roots.is_empty());
    }

    #[test]
    fn pinned_directory_is_not_retargeted_by_path_substitution() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let a = Uuid::new_v4();
        let dir = directory(base, a);
        let original = path(base, a);
        let moved = original.with_extension("moved");
        fs::rename(&original, &moved).unwrap();
        fs::create_dir(&original).unwrap();
        fs::set_permissions(&original, fs::Permissions::from_mode(0o700)).unwrap();
        dir.save(&AgentSettings::default()).unwrap();
        assert!(moved.join("settings.json").is_file());
        assert!(!original.join("settings.json").exists());
    }
}
