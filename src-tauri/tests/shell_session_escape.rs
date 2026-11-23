#![cfg(unix)]

// This is a negative containment fixture, NOT a sandbox implementation.
// We deliberately own BOTH processes as direct children, so a failing
// assertion cannot orphan an untracked escaped grandchild.
use std::{
    env,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::process::CommandExt,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const ESCAPE_CHILD_ENV: &str = "SECURITY_AGENT_TEST_ESCAPE_CHILD";
const ESCAPE_HEARTBEAT_ENV: &str = "SECURITY_AGENT_TEST_ESCAPE_HEARTBEAT";

struct OwnedSessionFixture {
    leader: Child,
    escaped: Option<Child>,
    group_id: libc::pid_t,
}

impl Drop for OwnedSessionFixture {
    fn drop(&mut self) {
        // The group leader has NOT been reaped. Its PID still pins the PGID,
        // so negative-PGID signalling cannot target a recycled unrelated group.
        // Do this BEFORE reaping either child, including on test panic.
        // SAFETY: the group_id is the live, owned and unreaped leader's PID.
        unsafe {
            libc::kill(-self.group_id, libc::SIGKILL);
        }
        if let Some(escaped) = self.escaped.as_mut() {
            // The escaped session is a *direct child* of this test process.
            // Retain its Child handle through kill + wait; never scan PIDs.
            let _ = escaped.kill();
            let _ = escaped.wait();
        }
        let _ = self.leader.kill();
        let _ = self.leader.wait();
    }
}

fn heartbeat_size(path: &std::path::Path) -> u64 {
    fs::metadata(path).map_or(0, |metadata| metadata.len())
}

#[test]
fn escaped_session_fixture_child() {
    if env::var(ESCAPE_CHILD_ENV).ok().as_deref() != Some("1") {
        return;
    }

    // The parent put this direct child in another CHILD's process group.
    // The child is not the group leader, so setsid() must succeed.
    // SAFETY: executed in an isolated test subprocess, never in the app.
    let session = unsafe { libc::setsid() };
    assert!(session > 1, "isolated fixture failed to call setsid");
    assert_eq!(session, std::process::id() as libc::pid_t);

    let heartbeat = env::var_os(ESCAPE_HEARTBEAT_ENV).expect("missing private heartbeat path");
    let mut output = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(heartbeat)
        .expect("fixture heartbeat cannot be created");

    loop {
        output.write_all(b"x").expect("heartbeat write failed");
        output.flush().expect("heartbeat flush failed");
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn process_group_kill_does_not_contain_a_setsid_descendant() {
    let private = tempfile::tempdir().expect("private fixture directory");
    let heartbeat = private.path().join("detached-heartbeat");

    // Isolated leader is a *direct child*, never this test process's group.
    // /bin/sleep exists on native macOS and Linux test runners.
    let leader = Command::new("/bin/sleep")
        .arg("30")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("cannot start owned process-group leader");
    let group_id = libc::pid_t::try_from(leader.id()).expect("invalid owned process ID");
    assert!(group_id > 1);
    let mut owned = OwnedSessionFixture {
        leader,
        escaped: None,
        group_id,
    };

    // Spawn the Rust test executable itself in the leader's process group.
    // We own this Child handle directly, unlike an untracked shell grandchild.
    // No shell quoting, untrusted command text or inherited stdout pipes.
    let exe = env::current_exe().expect("test executable");
    let escaped = Command::new(exe)
        .arg("--exact")
        .arg("escaped_session_fixture_child")
        .arg("--nocapture")
        .env(ESCAPE_CHILD_ENV, "1")
        .env(ESCAPE_HEARTBEAT_ENV, &heartbeat)
        .process_group(group_id)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("cannot start owned escaping child");
    owned.escaped = Some(escaped);
    let escaped_id =
        libc::pid_t::try_from(owned.escaped.as_ref().unwrap().id()).expect("invalid child PID");
    assert_ne!(escaped_id, group_id);

    let deadline = Instant::now() + Duration::from_secs(8);
    while heartbeat_size(&heartbeat) < 2 && Instant::now() < deadline {
        assert!(
            owned.escaped.as_mut().unwrap().try_wait().unwrap().is_none(),
            "escaping fixture exited before demonstrating setsid"
        );
        thread::sleep(Duration::from_millis(25));
    }
    assert!(
        heartbeat_size(&heartbeat) >= 2,
        "escaping fixture never produced a heartbeat"
    );

    // The detached subprocess is now its own session/group leader.
    // SAFETY: these syscalls query the still-owned, unreaped child PIDs.
    assert_eq!(unsafe { libc::getsid(escaped_id) }, escaped_id);
    assert_eq!(unsafe { libc::getpgid(escaped_id) }, escaped_id);
    assert_eq!(unsafe { libc::getpgid(group_id) }, group_id);

    // A normal process-group owner can kill the original group, but NOT
    // this malicious descendant that called setsid(). This is precisely why
    // tunnel HTTP shell remains fail-closed pending a stronger supervisor.
    // SAFETY: owned group leader has not been reaped; PGID cannot be reused.
    assert_eq!(unsafe { libc::kill(-group_id, libc::SIGKILL) }, 0);
    let prior = heartbeat_size(&heartbeat);
    thread::sleep(Duration::from_millis(250));
    assert!(
        heartbeat_size(&heartbeat) > prior,
        "expected escaped child to survive the old group's SIGKILL"
    );
    assert!(
        owned.escaped.as_mut().unwrap().try_wait().unwrap().is_none(),
        "escaped fixture unexpectedly exited"
    );
    // OwnedSessionFixture::drop always stops AND reaps both direct children,
    // including when an assertion above fails.
}
