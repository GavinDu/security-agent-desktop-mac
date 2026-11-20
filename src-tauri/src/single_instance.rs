//! Fail-closed, per-user instance lock for the Tauri host process.
//! Not an authorization or IPC channel. Keep lockfile after exit: unlinking
//! a locked inode would permit a second independent lock and split-brain.
use std::{
    fs::{self, File, OpenOptions, TryLockError},
    path::Path,
};

pub struct InstanceGuard {
    _lock: File,
}

impl InstanceGuard {
    pub fn acquire() -> Result<Self, String> {
        let home = dirs::home_dir().ok_or("Home directory unavailable")?;
        let path = home.join(
            "Library/Application Support/com.gavindu.securityagent.desktop/desktop-instance.lock",
        );
        Self::acquire_at(&path)
    }

    fn acquire_at(path: &Path) -> Result<Self, String> {
        let parent = path.parent().ok_or("Invalid instance lock directory")?;
        fs::create_dir_all(parent)
            .map_err(|_| "Cannot initialize desktop instance lock directory")?;

        // No lock contents, PID, secret or per-user paths are written.
        // Never follow an existing symlink to an arbitrary user file.
        match fs::symlink_metadata(path) {
            Ok(metadata) if !metadata.is_file() => {
                return Err("Unsafe desktop instance lock file".into());
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err("Cannot inspect desktop instance lock".into()),
        }

        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // Kernel-enforced on the opened descriptor. A prior
            // symlink_metadata(path) alone has a check/open race.
            opts.mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = opts
            .open(path)
            .map_err(|_| "Cannot open desktop instance lock")?;
        if !file
            .metadata()
            .map_err(|_| "Cannot inspect desktop instance lock")?
            .is_file()
        {
            return Err("Unsafe desktop instance lock file".into());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if file
                .metadata()
                .map_err(|_| "Cannot inspect desktop instance lock")?
                .permissions()
                .mode()
                & 0o777
                != 0o600
            {
                return Err("Desktop instance lock permissions must be 0600".into());
            }
            // An existing hardlink to a different private file is not a
            // dedicated instance lock. Checking the *opened* inode prevents
            // a 0600 hardlink from being mistaken for the app's lockfile.
            use std::os::unix::fs::MetadataExt;
            if file
                .metadata()
                .map_err(|_| "Cannot inspect desktop instance lock")?
                .nlink()
                != 1
            {
                return Err("Unsafe hard-linked desktop instance lock".into());
            }
        }

        match file.try_lock() {
            Ok(()) => Ok(Self { _lock: file }),
            Err(TryLockError::WouldBlock) => Err(
                "Security Agent is already running; use the existing menu-bar app to show its window"
                    .into(),
            ),
            Err(TryLockError::Error(_)) => Err("Cannot acquire desktop instance lock".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_process_cannot_acquire_guard_until_first_releases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("desktop-instance.lock");
        let first = InstanceGuard::acquire_at(&path).unwrap();
        let denied = InstanceGuard::acquire_at(&path);
        assert!(matches!(denied, Err(message) if message.contains("already running")));
        drop(first);
        assert!(InstanceGuard::acquire_at(&path).is_ok());
        // The lockfile stays in place after unlock; never unlink a locked inode.
        assert!(path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_private_hardlink_to_another_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("some-private-file");
        fs::write(&target, b"private value").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let lock_path = dir.path().join("desktop-instance.lock");
        fs::hard_link(&target, &lock_path).unwrap();
        assert!(InstanceGuard::acquire_at(&lock_path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"private value");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_leaf_after_metadata_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("external");
        fs::write(&target, b"untouched").unwrap();
        let path = dir.path().join("desktop-instance.lock");
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(InstanceGuard::acquire_at(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"untouched");
    }

    #[cfg(unix)]
    #[test]
    fn refuses_insecure_or_symlinked_instance_lock_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("desktop-instance.lock");
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(InstanceGuard::acquire_at(&path).is_err());
        fs::remove_file(&path).unwrap();
        symlink(dir.path().join("elsewhere"), &path).unwrap();
        assert!(InstanceGuard::acquire_at(&path).is_err());
    }
}
