//! Descriptor-anchored, fail-closed Unix reads beneath a user-granted directory.
use std::{
    ffi::OsStr,
    fs::{File, OpenOptions},
    io::Read,
    path::{Component, Path, PathBuf},
};

pub struct GrantedRoot {
    path: PathBuf,
    #[cfg(unix)]
    directory: File,
}

impl GrantedRoot {
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(unix)]
    pub fn clone_directory(&self) -> Result<File, String> {
        self.directory
            .try_clone()
            .map_err(|_| "Cannot retain approved directory".into())
    }
}

#[cfg(unix)]
fn open_component(
    parent: &File,
    component: &OsStr,
    extra_flags: libc::c_int,
) -> Result<File, String> {
    use std::ffi::CString;
    use std::os::unix::{
        ffi::OsStrExt,
        io::{AsRawFd, FromRawFd},
    };
    let name = CString::new(component.as_bytes()).map_err(|_| "Invalid approved path component")?;
    // SAFETY: parent owns a valid FD; name is a live NUL-terminated CString.
    // openat returns either an error or a distinct owned descriptor.
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | extra_flags,
        )
    };
    if fd < 0 {
        return Err("Cannot traverse approved path safely".into());
    }
    // SAFETY: positive openat return transfers ownership of this new FD once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

#[cfg(unix)]
pub fn pin_absolute_directory(path: &Path) -> Result<File, String> {
    use std::os::unix::fs::OpenOptionsExt;
    if !path.is_absolute() {
        return Err("Granted directory must be absolute".into());
    }
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let mut current = options
        .open("/")
        .map_err(|_| "Cannot pin filesystem root")?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = open_component(&current, name, libc::O_DIRECTORY | libc::O_NONBLOCK)?;
            }
            _ => return Err("Unsafe granted root component".into()),
        }
    }
    Ok(current)
}

pub fn canonical_roots(roots: &[String]) -> Result<Vec<GrantedRoot>, String> {
    let mut pinned: Vec<GrantedRoot> = Vec::new();
    for configured in roots {
        let path = std::fs::canonicalize(configured)
            .map_err(|_| "Configured granted root is unavailable")?;
        if pinned.iter().any(|root| root.path == path) {
            continue;
        }
        #[cfg(unix)]
        {
            let directory = pin_absolute_directory(&path)?;
            pinned.push(GrantedRoot { path, directory });
        }
        #[cfg(not(unix))]
        return Err("File grants require Unix directory descriptors".into());
    }
    Ok(pinned)
}

/// Never reinterpret a checked path as an absolute name after desktop approval.
/// Only Normal components may be opened, each relative to an owned directory FD.
#[cfg(unix)]
pub fn read_scoped_file(root: &File, relative: &Path) -> Result<String, String> {
    const MAX_FILE_BYTES: u64 = 64 * 1024;
    if relative.is_absolute() {
        return Err("Unsafe scoped file path".into());
    }
    let mut parts = relative.components().peekable();
    let mut parent = root
        .try_clone()
        .map_err(|_| "Cannot retain approved directory".to_owned())?;
    let mut file = None;
    while let Some(component) = parts.next() {
        let Component::Normal(name) = component else {
            return Err("Unsafe scoped file component".into());
        };
        if parts.peek().is_some() {
            parent = open_component(&parent, name, libc::O_DIRECTORY | libc::O_NONBLOCK)?;
        } else {
            file = Some(open_component(&parent, name, libc::O_NONBLOCK)?);
        }
    }
    let file = file.ok_or("Approved path must name a file")?;
    let metadata = file
        .metadata()
        .map_err(|_| "Cannot inspect approved file")?;
    if !metadata.is_file() || metadata.len() > MAX_FILE_BYTES {
        return Err("Not a regular file or file exceeds 64 KiB".into());
    }
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() != 1 {
        return Err("Hard-linked files cannot be read as a scoped grant".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Cannot read approved file")?;
    if bytes.len() as u64 > MAX_FILE_BYTES {
        return Err("File exceeds 64 KiB limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "Only UTF-8 files are supported".into())
}

#[cfg(not(unix))]
pub fn read_scoped_file(_root: &File, _relative: &Path) -> Result<String, String> {
    Err("Scoped reads require Unix directory descriptors".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn fixture(root: &Path, file: &str) -> Result<String, String> {
        let pinned = pin_absolute_directory(&root.canonicalize().unwrap())?;
        read_scoped_file(&pinned, Path::new(file))
    }

    #[cfg(unix)]
    #[test]
    fn preserves_leaf_type_nlink_utf8_and_64k_limit() {
        let root = tempfile::tempdir().unwrap();
        let leaf = root.path().join("file.txt");
        std::fs::write(&leaf, vec![b'x'; 65536]).unwrap();
        assert_eq!(fixture(root.path(), "file.txt").unwrap().len(), 65536);
        std::fs::write(&leaf, vec![b'x'; 65537]).unwrap();
        assert!(fixture(root.path(), "file.txt").is_err());
        std::fs::write(&leaf, [0xff_u8]).unwrap();
        assert!(fixture(root.path(), "file.txt").is_err());
        let link = root.path().join("link");
        std::os::unix::fs::symlink(&leaf, &link).unwrap();
        assert!(fixture(root.path(), "link").is_err());
        std::fs::hard_link(&leaf, root.path().join("hardlink")).unwrap();
        assert!(fixture(root.path(), "file.txt").is_err());
        assert!(fixture(root.path(), ".").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn pinned_root_is_not_replaced_by_renaming_the_granted_path() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("grant");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("document"), "original").unwrap();
        let pinned = pin_absolute_directory(&path.canonicalize().unwrap()).unwrap();
        std::fs::rename(&path, temp.path().join("old-grant")).unwrap();
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join("document"), "replacement-secret").unwrap();
        assert_eq!(
            read_scoped_file(&pinned, Path::new("document")).unwrap(),
            "original"
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_absolute_parent_and_symlinked_intermediate_components() {
        let temp = tempfile::tempdir().unwrap();
        let grant = temp.path().join("grant");
        let secret = temp.path().join("secret");
        std::fs::create_dir(&grant).unwrap();
        std::fs::create_dir(&secret).unwrap();
        std::fs::write(secret.join("file"), "not-granted").unwrap();
        let pinned = pin_absolute_directory(&grant.canonicalize().unwrap()).unwrap();
        std::os::unix::fs::symlink(&secret, grant.join("child")).unwrap();
        for name in [
            "/etc/passwd",
            "../secret/file",
            "child/file",
            "child/../file",
        ] {
            assert!(read_scoped_file(&pinned, Path::new(name)).is_err());
        }
    }
}
