//! Fail-closed, per-user instance lock for the Tauri host process.
//! Not an authorization or IPC channel. Keep lockfile after exit: unlinking
//! a locked inode would permit a second independent lock and split-brain.
use std::{
    fs::{self, File, TryLockError},
    path::Path,
};

#[cfg(not(unix))]
use std::fs::OpenOptions;

pub struct InstanceGuard {
    _lock: File,
}

impl InstanceGuard {
    // The GUI host owns private user Keychain and approved shell/filesystem
    // capabilities. A future launchd VPN service is a separate process and
    // must not accidentally elevate this interactive application.
    #[cfg(target_os = "macos")]
    fn validate_unprivileged_user(real_uid: libc::uid_t, effective_uid: libc::uid_t) -> Result<(), String> {
        if real_uid == 0 || effective_uid == 0 || real_uid != effective_uid {
            return Err("Desktop requires an unprivileged macOS user identity".into());
        }
        Ok(())
    }

    pub fn acquire() -> Result<Self, String> {
        // Reject elevated or setuid GUI startup before discovering home paths,
        // creating the singleton lock, reading Keychain or launching an agent.
        #[cfg(target_os = "macos")]
        Self::validate_unprivileged_user(unsafe { libc::getuid() }, unsafe { libc::geteuid() })?;

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

        // Pin the containing directory before resolving the leaf. A leaf-only
        // O_NOFOLLOW path open would still follow a substituted parent.
        #[cfg(unix)]
        let file = Self::open_lock_in_pinned_directory(parent, path)?;
        #[cfg(not(unix))]
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
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

    /// Pin the final Application Support directory with the kernel, then
    /// resolve only the lock basename relative to that checked descriptor.
    /// This does not make arbitrary same-UID directory renames impossible.
    #[cfg(unix)]
    fn open_lock_in_pinned_directory(parent: &Path, path: &Path) -> Result<File, String> {
        use std::ffi::CString;
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};

        let dir_name = CString::new(parent.as_os_str().as_bytes())
            .map_err(|_| "Invalid desktop instance lock directory")?;
        // O_NOFOLLOW applies to the directory leaf. Retain the FD until the
        // relative lockfile open completes; never trust only metadata by name.
        let dir_fd = unsafe {
            libc::open(
                dir_name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if dir_fd < 0 {
            return Err("Cannot safely open desktop instance lock directory".into());
        }
        // SAFETY: a successful open returns a uniquely owned descriptor.
        let directory = unsafe { File::from_raw_fd(dir_fd) };
        let metadata = directory
            .metadata()
            .map_err(|_| "Cannot inspect desktop instance lock directory")?;
        if !metadata.is_dir()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o022 != 0
        {
            return Err("Unsafe desktop instance lock directory".into());
        }

        let name = path
            .file_name()
            .ok_or("Invalid desktop instance lock filename")?;
        let leaf =
            CString::new(name.as_bytes()).map_err(|_| "Invalid desktop instance lock filename")?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            return Err("Cannot open desktop instance lock".into());
        }
        // SAFETY: a successful openat returns a uniquely owned descriptor.
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn desktop_rejects_root_setuid_and_mismatched_macos_identity() {
        for (real, effective) in [(0, 0), (0, 501), (501, 0), (501, 502)] {
            assert_eq!(
                InstanceGuard::validate_unprivileged_user(real, effective),
                Err("Desktop requires an unprivileged macOS user identity".into()),
                "real={real}, effective={effective}",
            );
        }
        for uid in [1, 501, 65534] {
            assert!(
                InstanceGuard::validate_unprivileged_user(uid, uid).is_ok(),
                "unprivileged same-UID launch should be accepted",
            );
        }
    }

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
    fn refuses_symlinked_containing_directory_without_creating_lock() {
        let dir = tempfile::tempdir().unwrap();
        let actual = dir.path().join("actual");
        fs::create_dir(&actual).unwrap();
        let substitute = dir.path().join("application-support");
        std::os::unix::fs::symlink(&actual, &substitute).unwrap();
        let error = match InstanceGuard::acquire_at(&substitute.join("desktop-instance.lock")) {
            Ok(_) => panic!("must reject symlinked lock parent"),
            Err(error) => error,
        };
        assert!(error.contains("lock directory"));
        assert!(!actual.join("desktop-instance.lock").exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_group_writable_containing_directory_before_lock_creation() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("application-support");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o770)).unwrap();
        let path = parent.join("desktop-instance.lock");
        let error = match InstanceGuard::acquire_at(&path) {
            Ok(_) => panic!("must reject writable lock parent"),
            Err(error) => error,
        };
        assert_eq!(error, "Unsafe desktop instance lock directory");
        assert!(!path.exists());
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
