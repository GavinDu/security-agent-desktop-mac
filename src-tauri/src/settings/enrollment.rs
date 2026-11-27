//! Trusted-host enrollment metadata. Never infer authority from directory
//! existence, legacy settings, or an account UUID supplied by a renderer.
use super::{
    checked_settings_directory, open_settings_at,
    scoped_settings::{private_child, AccountSettingsDirectory},
};
use crate::account_credentials::AccountId;
use serde::{Deserialize, Serialize};
use std::{
    ffi::CString,
    fs::File,
    io::{self, Read, Write},
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
use uuid::Uuid;

const MAX_ACCOUNTS: usize = 32;
const MAX_BYTES: u64 = 8192;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    version: u32,
    accounts: Vec<AccountId>,
}

fn checked_leaf(file: &File) -> Result<(), String> {
    let meta = file.metadata().map_err(|_| "Enrollment unavailable")?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || meta.len() > MAX_BYTES
    {
        return Err("Unsafe enrollment file".into());
    }
    Ok(())
}

pub(crate) struct EnrollmentStore {
    root: File,
    // Hold the advisory writer lock for the entire owner lifetime.
    _lock: File,
    manifest: Manifest,
    usable: bool,
}

impl EnrollmentStore {
    pub(crate) fn open(support: &Path) -> Result<Self, String> {
        let base = checked_settings_directory(support).map_err(|_| "Enrollment unavailable")?;
        let root = private_child(&base, &CString::new("accounts-v1").unwrap(), true)
            .map_err(|_| "Enrollment unavailable")?;
        let lock = open_settings_at(
            &root,
            &CString::new(".enrollment.lock").unwrap(),
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|_| "Enrollment lock unavailable")?;
        checked_leaf(&lock)?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("Enrollment already owned".into());
        }
        let leaf = CString::new("enrollment-v1.json").unwrap();
        let manifest = match open_settings_at(
            &root,
            &leaf,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => {
                checked_leaf(&file)?;
                let mut bytes = Vec::new();
                file.take(MAX_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(|_| "Enrollment read failed")?;
                if bytes.len() as u64 > MAX_BYTES {
                    return Err("Enrollment oversized".into());
                }
                serde_json::from_slice::<Manifest>(&bytes).map_err(|_| "Invalid enrollment")?
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Manifest {
                version: 1,
                accounts: Vec::new(),
            },
            Err(_) => return Err("Enrollment unavailable".into()),
        };
        if manifest.version != 1
            || manifest.accounts.len() > MAX_ACCOUNTS
            || manifest
                .accounts
                .iter()
                .enumerate()
                .any(|(i, id)| id.as_uuid().is_nil() || manifest.accounts[..i].contains(id))
        {
            return Err("Invalid enrollment".into());
        }
        Ok(Self {
            root,
            _lock: lock,
            manifest,
            usable: true,
        })
    }

    pub(crate) fn accounts(&self) -> Result<&[AccountId], String> {
        if !self.usable {
            return Err("Enrollment state unavailable".into());
        }
        Ok(&self.manifest.accounts)
    }

    pub(crate) fn enroll(&mut self) -> Result<AccountId, String> {
        if self.accounts()?.len() >= MAX_ACCOUNTS {
            return Err("Enrollment capacity exceeded".into());
        }
        let id = AccountId::issue();
        let leaf = CString::new(id.as_uuid().to_string()).unwrap();
        // Never adopt a pre-existing directory, even on a UUID collision.
        if unsafe { libc::mkdirat(self.root.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
            return Err("Enrollment directory creation failed".into());
        }
        let dir = AccountSettingsDirectory::open_under(&self.root, &leaf, false)?
            .ok_or("Enrollment directory unavailable")?;
        dir.save(&Default::default())?;
        let mut next = Manifest {
            version: 1,
            accounts: self.manifest.accounts.clone(),
        };
        next.accounts.push(id);
        // Any error after beginning manifest publication is uncertain.
        // Leave this owner unavailable until explicit restart/readback.
        self.usable = false;
        self.persist(&next)?;
        self.manifest = next;
        self.usable = true;
        Ok(id)
    }

    pub(super) fn open_account(&self, id: AccountId) -> Result<AccountSettingsDirectory, String> {
        if !self.accounts()?.contains(&id) {
            return Err("Account not enrolled".into());
        }
        let leaf = CString::new(id.as_uuid().to_string()).unwrap();
        AccountSettingsDirectory::open_under(&self.root, &leaf, false)?
            .ok_or_else(|| "Enrolled account unavailable".into())
    }

    fn persist(&self, manifest: &Manifest) -> Result<(), String> {
        let bytes = serde_json::to_vec(manifest).map_err(|_| "Enrollment encode failed")?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("Enrollment oversized".into());
        }
        let leaf = CString::new("enrollment-v1.json").unwrap();
        let temp = CString::new(format!(".enrollment-{}.tmp", Uuid::new_v4())).unwrap();
        let mut file = open_settings_at(
            &self.root,
            &temp,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
        .map_err(|_| "Enrollment temporary file unavailable")?;
        let result = (|| -> Result<(), String> {
            file.write_all(&bytes)
                .map_err(|_| "Enrollment write failed")?;
            file.sync_all().map_err(|_| "Enrollment sync failed")?;
            if unsafe {
                libc::renameat(
                    self.root.as_raw_fd(),
                    temp.as_ptr(),
                    self.root.as_raw_fd(),
                    leaf.as_ptr(),
                )
            } != 0
            {
                return Err("Enrollment replace failed".into());
            }
            self.root
                .sync_all()
                .map_err(|_| "Enrollment directory sync failed")?;
            Ok(())
        })();
        if result.is_err() {
            // Only the create-exclusive temp, never committed metadata.
            unsafe { libc::unlinkat(self.root.as_raw_fd(), temp.as_ptr(), 0) };
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
    };

    #[test]
    fn enrollment_survives_restart_without_adopting_legacy_or_unlisted_directory() {
        let base = tempfile::tempdir().unwrap();
        fs::write(base.path().join("settings.json"), b"legacy authority").unwrap();
        let mut store = EnrollmentStore::open(base.path()).unwrap();
        assert!(store.accounts().unwrap().is_empty());
        assert!(EnrollmentStore::open(base.path()).is_err());
        let account = store.enroll().unwrap();
        let unknown = AccountId::issue();
        let root = base.path().join("accounts-v1");
        fs::create_dir(root.join(unknown.as_uuid().to_string())).unwrap();
        fs::set_permissions(
            root.join(unknown.as_uuid().to_string()),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        assert!(store.open_account(unknown).is_err());
        drop(store);
        let store = EnrollmentStore::open(base.path()).unwrap();
        assert!(store.accounts().unwrap() == [account]);
        assert!(store
            .open_account(account)
            .unwrap()
            .load()
            .unwrap()
            .allowed_roots
            .is_empty());
        assert!(store.open_account(unknown).is_err());
        assert_eq!(
            fs::read(base.path().join("settings.json")).unwrap(),
            b"legacy authority"
        );
    }

    #[test]
    fn corrupt_and_unsafe_manifest_fails_closed() {
        let base = tempfile::tempdir().unwrap();
        let mut store = EnrollmentStore::open(base.path()).unwrap();
        let account = store.enroll().unwrap();
        drop(store);
        let leaf = base.path().join("accounts-v1/enrollment-v1.json");
        let id = account.as_uuid();
        for bytes in [
            format!(r#"{{"version":1,"accounts":["{id}","{id}"]}}"#),
            format!(r#"{{"version":1,"accounts":["{}"]}}"#, Uuid::nil()),
            r#"{"version":2,"accounts":[]}"#.into(),
            r#"{"version":1,"accounts":[],"active":"forbidden"}"#.into(),
            r#"{"version":1,"version":1,"accounts":[]}"#.into(),
            "x".repeat(MAX_BYTES as usize + 1),
        ] {
            fs::write(&leaf, bytes).unwrap();
            assert!(EnrollmentStore::open(base.path()).is_err());
        }
        fs::remove_file(&leaf).unwrap();
        let target = base.path().join("other");
        fs::write(&target, r#"{"version":1,"accounts":[]}"#).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &leaf).unwrap();
        assert!(EnrollmentStore::open(base.path()).is_err());
        fs::remove_file(&leaf).unwrap();
        fs::hard_link(&target, &leaf).unwrap();
        assert!(EnrollmentStore::open(base.path()).is_err());
    }
}
