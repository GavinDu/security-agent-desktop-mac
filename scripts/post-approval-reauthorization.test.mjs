import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

test('post-approval policy and grant changes deny stale shell/file dispatch (#121)', async () => {
  const source = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(source, /fn reauthorize_after_approval\(&self, tool: &str, approved: &Path\)/);
  assert.match(source, /self\.gate\.policy\(tool\) == Policy::Disable/);
  assert.match(source, /let current = self\.allowed_path\(approved\)\?/);
  assert.match(source, /if current != approved/);
  assert.match(source, /self\.reauthorize_after_approval\("filesystem__read_file", &path\)\?/);
  assert.match(source, /self\.reauthorize_after_approval\("bash__run", &directory\)\?/);
  assert.match(source, /async fn revoked_root_after_approval_request_cannot_launch_bash/);
  assert.match(source, /async fn disabling_file_tool_during_approval_denies_stale_approval/);
  assert.match(source, /async fn replacing_approved_file_name_during_approval_is_denied/);
  const requireEnd = source.indexOf('.await?;', source.indexOf('.require("filesystem__read_file"'));
  const fileRecheck = source.indexOf('self.reauthorize_after_approval("filesystem__read_file", &path)', requireEnd);
  const fileSpawn = source.indexOf('tokio::task::spawn_blocking', fileRecheck);
  assert.ok(requireEnd > 0 && fileRecheck > requireEnd && fileSpawn > fileRecheck);
  const shellRecheck = source.indexOf('self.reauthorize_after_approval("bash__run", &directory)');
  const shellSpawn = source.indexOf('Command::new("/bin/sh")', shellRecheck);
  assert.ok(shellRecheck > 0 && shellSpawn > shellRecheck);
});
