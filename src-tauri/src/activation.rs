//! Same-user, activation-only macOS handoff for a *rejected* second GUI launch.
//! The per-user InstanceGuard remains the singleton authority. This socket
//! cannot execute tools, accept URLs or create a privileged WebView.
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    time::Duration,
};
use tauri::Manager;

const FOCUS_REQUEST: u8 = b'F';
const MAX_REQUEST_BYTES: u64 = 2;
const PEER_READ_DEADLINE: Duration = Duration::from_millis(250);

fn activation_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or("Home directory unavailable")?;
    Ok(home
        .join(crate::single_instance::DESKTOP_PRIVATE_DIRECTORY)
        .join("desktop-focus.sock"))
}

// The InstanceGuard checks its pinned private directory before it can be
// acquired. Repeat the ownership/mode check before creating a named socket;
// a same-UID adversary can rename its own directories, but cannot gain tools,
// secrets or authorization through this focus-only channel.
fn checked_parent(path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or("Invalid desktop activation directory")?;
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| "Cannot inspect desktop activation directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o022 != 0
    {
        return Err("Unsafe desktop activation directory".into());
    }
    Ok(())
}

fn checked_socket(path: &Path) -> Result<(), String> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| "Cannot inspect desktop activation socket")?;
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("Unsafe desktop activation socket".into());
    }
    Ok(())
}

fn bind_at(path: &Path) -> Result<UnixListener, String> {
    checked_parent(path)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            // Never unlink a socket that could belong to an active listener.
            checked_socket(path)?;
            match UnixStream::connect(path) {
                Ok(_) => return Err("Desktop activation socket already active".into()),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionRefused | std::io::ErrorKind::NotFound
                    ) => {}
                Err(_) => return Err("Cannot inspect desktop activation listener".into()),
            }
            // The singleton guard is held by this primary before stale cleanup.
            // No other UID can replace entries inside the verified directory.
            fs::remove_file(path).map_err(|_| "Cannot remove stale desktop activation socket")?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("Cannot inspect desktop activation socket".into()),
    }

    let listener = UnixListener::bind(path).map_err(|_| "Cannot bind desktop activation socket")?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|_| "Cannot protect desktop activation socket")?;
    checked_socket(path)?;
    Ok(listener)
}

fn peer_is_same_user(stream: &UnixStream) -> bool {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: the accepted stream owns a valid socket FD; kernel supplies
    // credentials, not an untrusted claim in the request body.
    unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) == 0 }
        && uid == unsafe { libc::geteuid() }
}

fn exact_focus_request(stream: &mut UnixStream) -> bool {
    if stream.set_read_timeout(Some(PEER_READ_DEADLINE)).is_err() {
        return false;
    }
    let mut bytes = Vec::with_capacity(MAX_REQUEST_BYTES as usize);
    // Require EOF after one fixed marker; reject unknown/extra payload,
    // including any attempt to forward argv, cwd or a deep link.
    stream
        .take(MAX_REQUEST_BYTES)
        .read_to_end(&mut bytes)
        .is_ok()
        && bytes.as_slice() == [FOCUS_REQUEST]
}

fn request_at(path: &Path) -> Result<(), String> {
    checked_parent(path)?;
    checked_socket(path)?;
    let mut peer =
        UnixStream::connect(path).map_err(|_| "Existing desktop activation unavailable")?;
    peer.set_write_timeout(Some(PEER_READ_DEADLINE))
        .map_err(|_| "Existing desktop activation unavailable")?;
    peer.write_all(&[FOCUS_REQUEST])
        .map_err(|_| "Existing desktop activation unavailable")?;
    peer.shutdown(std::net::Shutdown::Write)
        .map_err(|_| "Existing desktop activation unavailable")?;
    Ok(())
}

/// Only a precise singleton WouldBlock error permits requesting focus.
/// Failures never bypass the lock or create a fallback agent.
pub(crate) fn request_focus_existing() -> Result<(), String> {
    request_at(&activation_path()?)
}

/// The listener is installed only after singleton acquisition, trusted main
/// WebView construction and tray registration. Its thread lives until exit.
pub(crate) fn install(app: &tauri::AppHandle) -> Result<(), String> {
    let listener = bind_at(&activation_path()?)?;
    let app = app.clone();
    std::thread::Builder::new()
        .name("desktop-focus-handoff".into())
        .spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut peer) = incoming else {
                    break;
                };
                if !peer_is_same_user(&peer) || !exact_focus_request(&mut peer) {
                    continue;
                }
                let on_main = app.clone();
                // AppKit focus must run on Tauri's main thread; the socket
                // thread must never manufacture another window or invoke IPC.
                let _ = app.run_on_main_thread(move || crate::tray::show_main(&on_main));
            }
        })
        .map_err(|_| "Cannot start desktop activation listener".to_owned())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Shutdown;

    fn checked_temp_path(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("desktop-focus.sock")
    }

    #[test]
    fn same_uid_socket_pair_is_validated_by_kernel() {
        let (server, _client) = UnixStream::pair().unwrap();
        assert!(peer_is_same_user(&server));
    }

    #[test]
    fn accepts_only_exact_marker_and_eof() {
        for (payload, valid) in [
            (b"F".as_slice(), true),
            (b"FF".as_slice(), false),
            (b"X".as_slice(), false),
            (b"".as_slice(), false),
            (b"Fhttps://example.com".as_slice(), false),
        ] {
            let (mut server, mut client) = UnixStream::pair().unwrap();
            client.write_all(payload).unwrap();
            client.shutdown(Shutdown::Write).unwrap();
            assert_eq!(exact_focus_request(&mut server), valid);
        }
    }

    #[test]
    fn refuses_symlinks_and_non_socket_targets() {
        let dir = tempfile::tempdir().unwrap();
        let path = checked_temp_path(&dir);
        let target = dir.path().join("private");
        fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(bind_at(&path).is_err());
        assert!(request_at(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"keep");
    }

    #[test]
    fn stale_socket_is_recovered_but_active_socket_is_not_unlinked() {
        let dir = tempfile::tempdir().unwrap();
        let path = checked_temp_path(&dir);
        let first = bind_at(&path).unwrap();
        assert!(bind_at(&path).is_err());
        assert!(path.exists());
        drop(first);
        let second = bind_at(&path).unwrap();
        assert!(path.exists());
        drop(second);
    }

    #[test]
    fn rejected_second_launch_sends_one_constant_byte_to_first_instance() {
        let dir = tempfile::tempdir().unwrap();
        let path = checked_temp_path(&dir);
        let listener = bind_at(&path).unwrap();
        request_at(&path).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        assert!(peer_is_same_user(&peer));
        assert!(exact_focus_request(&mut peer));
    }

    #[test]
    fn rejects_permissive_socket_mode() {
        let dir = tempfile::tempdir().unwrap();
        let path = checked_temp_path(&dir);
        let listener = bind_at(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(request_at(&path).is_err());
        assert!(bind_at(&path).is_err());
        drop(listener);
    }
}
