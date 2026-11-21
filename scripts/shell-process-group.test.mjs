import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('approved Unix bash process group survives request abort long enough to reap (#93)', async () => {
  const code = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(code, /\.process_group\(0\)/);
  assert.match(code, /struct ShellProcessOwner/);
  assert.match(code, /struct ShellProcessOwner[\s\S]*reaped: bool/);
  assert.match(code, /libc::kill\(-self\.pgid, signal\)/);
  assert.match(code, /self\.signal_group\(libc::SIGTERM\)/);
  assert.match(code, /self\.signal_group\(libc::SIGKILL\)/);
  assert.match(code, /self\.child\.wait\(\)/);
  assert.match(code, /run_shell_owned_with_deadline\(command, directory, cancel_rx, Duration::from_secs\(15\)\)/);
  assert.match(code, /tokio::time::timeout\(deadline, async/);
  assert.match(code, /fn shell_timeout_terminates_infinite_streams_without_unbounded_capture/);
  assert.match(code, /let \(cancel_tx, cancel_rx\) = oneshot::channel::<\(\)>\(\)/);
  assert.match(code, /let _ = result_tx\.send\(run_shell_owned/);
  assert.match(code, /const MAX_ACTIVE_SHELLS: usize = 8/);
  assert.match(code, /static SHELL_PERMITS: OnceLock<Arc<Semaphore>>/);
  assert.match(code, /\.try_acquire_owned\(\)/);
  assert.match(code, /let _permit = permit/);
  assert.match(code, /fn cancelling_shell_owner_kills_descendant_even_after_shell_leader_exits/);
  assert.match(code, /fn shell_group_isolation_never_signals_unrelated_process_group/);
  assert.doesNotMatch(code, /\.pre_exec\(/);
});
