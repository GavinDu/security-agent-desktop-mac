import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('forced second launch uses only the singleton WouldBlock result and runs before Keychain (#189)', async () => {
  const app = await readFile('src-tauri/src/app.rs', 'utf8');
  const single = await readFile('src-tauri/src/single_instance.rs', 'utf8');
  const activation = await readFile('src-tauri/src/activation.rs', 'utf8');
  const lib = await readFile('src-tauri/src/lib.rs', 'utf8');

  assert.match(lib, /#\[cfg\(target_os = "macos"\)\]\s*mod activation;/);
  assert.match(single, /Err\(TryLockError::WouldBlock\) => Err\(ALREADY_RUNNING.into\(\)\)/);
  assert.match(app, /match crate::single_instance::InstanceGuard::acquire\(\)/);
  assert.match(app, /if error == crate::single_instance::ALREADY_RUNNING \{/);
  assert.match(app, /crate::activation::request_focus_existing\(\)/);
  assert.match(app, /return Err\(std::io::Error::other\(error\).into\(\)\)/);

  const lock = app.indexOf('InstanceGuard::acquire()');
  const handoff = app.indexOf('request_focus_existing()');
  const token = app.indexOf('secrets::get_or_create_api_token()');
  assert.ok(lock > 0 && handoff > lock && token > handoff);
  assert.match(app, /tray::install\(app\)\?;[\s\S]*crate::activation::install\(app.handle\(\)\)/);
  assert.match(activation, /crate::single_instance::DESKTOP_PRIVATE_DIRECTORY/);
});

test('activation socket enforces kernel peer UID and one bounded marker, no arbitrary IPC (#189)', async () => {
  const source = await readFile('src-tauri/src/activation.rs', 'utf8');
  const tray = await readFile('src-tauri/src/tray.rs', 'utf8');
  assert.match(source, /libc::getpeereid\(/);
  assert.match(source, /allowed_peer_uid\(uid, unsafe \{ libc::geteuid\(\) \}\)/);
  assert.match(source, /owner_uid != 0 && peer_uid == owner_uid/);
  assert.match(source, /const FOCUS_REQUEST: u8 = b'F';/);
  assert.match(source, /const FOCUS_ACCEPTED: u8 = b'A';/);
  assert.match(source, /peer.read_exact\(&mut acknowledged\)/);
  assert.match(source, /peer.write_all\(&\[FOCUS_ACCEPTED\]\)/);
  assert.match(source, /if acknowledged\[0\] != FOCUS_ACCEPTED/);
  assert.match(source, /const MAX_REQUEST_BYTES: u64 = 2;/);
  assert.match(source, /set_read_timeout\(Some\(PEER_READ_DEADLINE\)\)/);
  assert.match(source, /bytes.as_slice\(\) == \[FOCUS_REQUEST\]/);
  assert.match(source, /metadata.file_type\(\).is_socket\(\)/);
  assert.match(source, /metadata.nlink\(\) != 1/);
  assert.match(source, /metadata.mode\(\) & 0o777 != 0o600/);
  assert.match(source, /checked_parent\(path\)\?/);
  assert.match(source, /Desktop activation socket already active/);
  assert.match(source, /run_on_main_thread\(move \|\| crate::tray::show_main\(&on_main\)\)/);
  assert.match(tray, /get_webview_window\("main"\)/);
  assert.equal((source.match(/UnixListener::bind\(/g) || []).length, 1);
  const production = source.split('#[cfg(test)]')[0];
  assert.doesNotMatch(production, /invoke_tool|set_allowed_roots|AgentState::new|WebviewWindowBuilder|http:\/\/|https:\/\/|\.arg\(/);
});

test('negative ACK tests call production verifier without a timing-dependent second client (#214)', async () => {
  const source = await readFile('src-tauri/src/activation.rs', 'utf8');
  assert.match(source, /fn read_focus_ack\(peer: &mut UnixStream\) -> Result<\(\), String>/);
  const production = source.slice(source.indexOf('fn request_at('), source.indexOf('/// Only a precise singleton'));
  assert.match(production, /peer\.shutdown\(std::net::Shutdown::Write\)/);
  assert.match(production, /read_focus_ack\(&mut peer\)/);
  assert.match(production, /peer\.read_exact\(&mut acknowledged\)/);
  assert.match(production, /if acknowledged\[0\] != FOCUS_ACCEPTED/);
  const negative = source.slice(source.indexOf('fn refuses_invalid_or_missing_primary_ack('),
    source.indexOf('fn rejects_permissive_socket_mode('));
  assert.match(negative, /UnixStream::pair\(\)/);
  assert.match(negative, /for response in \[b"X"\.as_slice\(\), b""\.as_slice\(\)\]/);
  assert.match(negative, /read_focus_ack\(&mut client\)\.is_err\(\)/);
  assert.match(negative, /read_focus_ack\(&mut client\)\.is_ok\(\)/);
  assert.doesNotMatch(negative, /std::thread::spawn|request_at\(&sender_path\)|listener\.accept\(\)/);
  assert.match(source, /fn rejected_second_launch_sends_one_constant_byte_to_first_instance\(\)/);
  assert.match(source, /const PEER_READ_DEADLINE: Duration = Duration::from_millis\(750\)/);
});

test('activation handoff retains macOS native tests and physical acceptance remains separate (#189)', async () => {
  const source = await readFile('src-tauri/src/activation.rs', 'utf8');
  const doc = await readFile('docs/SECOND_INSTANCE_FOCUS.md', 'utf8');
  for (const testName of [
    'rejects_foreign_or_root_uid_even_with_matching_socket_bytes',
    'same_uid_socket_pair_is_validated_by_kernel',
    'accepts_only_exact_marker_and_eof',
    'refuses_symlinks_and_non_socket_targets',
    'stale_socket_is_recovered_but_active_socket_is_not_unlinked',
    'rejected_second_launch_sends_one_constant_byte_to_first_instance',
    'refuses_invalid_or_missing_primary_ack',
    'rejects_permissive_socket_mode',
  ]) {
    assert.ok(source.includes('fn ' + testName + '('), 'missing native test: ' + testName);
  }
  assert.match(doc, /#72/);
  assert.match(doc, /physical Apple Silicon/);
  assert.match(doc, /no.*Keychain|no Keychain/i);
});
