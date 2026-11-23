import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile, mkdir, mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditSavedSettings } from './smoke-settings.mjs';

const json = async (path) => JSON.parse(await readFile(path, 'utf8'));
const config = await json('src-tauri/tauri.conf.json');
const capability = await json('src-tauri/capabilities/default.json');

test('the only configured privileged desktop WebView must be created with navigation guards', () => {
  assert.equal(config.app.windows.length, 1);
  assert.equal(config.app.windows[0].label, 'main');
  assert.equal(config.app.windows[0].create, false);
  assert.equal(config.app.withGlobalTauri, false);
  assert.equal(config.identifier, 'com.gavindu.securityagent.desktop');
});

test('native WebView must install trusted navigation and popup deny hooks before build', async () => {
  const source = await readFile('src-tauri/src/app.rs', 'utf8');
  const constructors = source.match(/WebviewWindowBuilder::from_config\(/g) ?? [];
  assert.equal(constructors.length, 1, 'exactly one window should be created with explicit guards');
  assert.doesNotMatch(source, /WebviewWindowBuilder::new\(/, 'no unguarded second window builder');
  const start = source.indexOf('WebviewWindowBuilder::from_config(app, &window_config)');
  const navigation = source.indexOf('.on_navigation(navigation::trusted_main_document)', start);
  const popup = source.indexOf(
    '.on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny)', navigation
  );
  const built = source.indexOf('.build()?', popup);
  assert.ok(start >= 0 && navigation > start && popup > navigation && built > popup,
    'both origin navigation and popup guards must be installed before native WebView build');
});

test('CSP prevents remote JS, frames, forms and active third-party resources', () => {
  const csp = config.app.security.csp;
  for (const directive of [
    "default-src 'self'", "script-src 'self'", "style-src 'self'",
    "object-src 'none'", "base-uri 'none'", "frame-src 'none'",
    "form-action 'none'", "worker-src 'none'", "media-src 'none'",
  ]) assert.ok(csp.includes(directive), directive);
  assert.ok(!csp.includes('https:'), 'do not open generic HTTPS script access');
});

test('main window is sole ACL receiver and event listeners are the only core grants', () => {
  assert.deepEqual(capability.windows, ['main']);
  assert.ok(!('remote' in capability), 'never enable remote origins');
  assert.deepEqual(
    [...capability.permissions].sort(),
    ['core:event:allow-listen', 'core:event:allow-unlisten'].sort()
  );
});

test('WebView distribution is entirely locally bundled', async () => {
  const html = await readFile('src-tauri/dist/index.html', 'utf8');
  const script = await readFile('src-tauri/dist/app.js', 'utf8');
  const stylesheet = await readFile('src-tauri/dist/app.css', 'utf8');
  assert.match(html, /<script src="app\.js" defer><\/script>/);
  assert.match(html, /href="app\.css"/);
  assert.ok(script.length > 100);
  assert.ok(stylesheet.length > 100);
  assert.doesNotMatch(html, /<iframe\b|<form\b|https?:\/\//i);
});

test('each privileged Tauri command checks caller window identity and URL before execution', async () => {
  for (const [file, expected] of [
    ['src-tauri/src/tools/commands.rs', 8],
    ['src-tauri/src/vpn/commands.rs', 1],
  ]) {
    const code = await readFile(file, 'utf8');
    const commands = code.match(/#\[tauri::command\]/g) ?? [];
    const guards = code.match(/navigation::ensure_privileged_webview\(&window\)\?/g) ?? [];
    assert.equal(commands.length, expected, `Unexpected command count in ${file}`);
    assert.equal(guards.length, commands.length,
      `Every command must enforce trusted sender window/origin in ${file}`);
  }
});

test('tool approval previews are emitted only to the trusted main window', async () => {
  const source = await readFile('src-tauri/src/app.rs', 'utf8');
  assert.match(source, /handle\.emit_to\(\s*"main",\s*"security-agent:\/\/tool-approval",\s*event\)/);
  assert.doesNotMatch(source, /handle\.emit\(\s*"security-agent:\/\/tool-approval"/);
});

test('CLI settings audit sees default-deny and redacts granted paths', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'security-agent-audit-'));
  try {
    const path = join(temp, 'settings.json');
    assert.deepEqual(await auditSavedSettings(path),
      { saved: false, rootCount: 0, policyCount: 0 });
    const root = join(temp, 'private-root');
    await mkdir(root);
    await writeFile(path, JSON.stringify({
      allowed_roots: [root],
      policies: { bash__run: 'ask', filesystem__read_file: 'auto' },
    }), { mode: 0o600 });
    await chmod(path, 0o600);
    const result = await auditSavedSettings(path);
    assert.deepEqual(result, { saved: true, rootCount: 1, policyCount: 2 });
    assert.ok(!JSON.stringify(result).includes(root), 'private root path must not be returned');
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('CLI settings audit refuses public, symlinked, malformed and unavailable grants without path leaks', async () => {
  const temp = await mkdtemp(join(tmpdir(), 'security-agent-audit-'));
  try {
    const file = join(temp, 'settings.json');
    const allowed = join(temp, 'allowed');
    await mkdir(allowed);
    const valid = { allowed_roots: [allowed], policies: { bash__run: 'disable' } };
    const save = async (value) => {
      await writeFile(file, typeof value === 'string' ? value : JSON.stringify(value));
      await chmod(file, 0o600);
    };
    await save(valid);
    await chmod(file, 0o644);
    await assert.rejects(auditSavedSettings(file), /private 0600/);
    await save('{');
    await assert.rejects(auditSavedSettings(file), /JSON is unreadable/);
    await save({ ...valid, unknown: true });
    await assert.rejects(auditSavedSettings(file), /unknown field/);
    await save({ ...valid, policies: { bash__run: 'permit_all' } });
    await assert.rejects(auditSavedSettings(file), /invalid tool policy/);
    await save({ ...valid, allowed_roots: ['relative-root'] });
    await assert.rejects(auditSavedSettings(file), /not an absolute directory/);
    const secret = join(temp, 'secret-personal-folder');
    await save({ ...valid, allowed_roots: [secret] });
    await assert.rejects(auditSavedSettings(file), (error) => {
      assert.match(error.message, /configured root is unavailable/);
      assert.ok(!error.message.includes(secret), 'failure must not reveal a user path');
      return true;
    });
    await rm(file);
    await symlink(join(temp, 'nonexistent-private-file'), file);
    await assert.rejects(auditSavedSettings(file), /Cannot safely open saved settings/);
  } finally {
    await rm(temp, { recursive: true, force: true });
  }
});

test('developer installer is ad-hoc signed as a complete app bundle, without elevated entitlements', () => {
  assert.equal(config.bundle.macOS.signingIdentity, '-');
  assert.equal(config.bundle.macOS.entitlements, undefined);
});

test('mounted unsigned DMG verifier fails closed on failed entitlement extraction', async () => {
  const code = await readFile('scripts/verify-macos-bundle.sh', 'utf8');
  assert.match(code, /codesign --verify --strict/);
  assert.match(code, /if ! \/usr\/bin\/codesign --display --entitlements/);
  assert.match(code, /refusing to assume none/);
});


test('instance lock leaf protection is enforced on open, not only in preflight (#79)', async () => {
  const source = await readFile('src-tauri/src/single_instance.rs', 'utf8');
  const preflight = source.indexOf('fs::symlink_metadata(path)');
  const call = source.indexOf('Self::open_lock_in_pinned_directory(parent, path)?');
  const locked = source.indexOf('file.try_lock()');
  const directory = source.indexOf('libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC');
  const openat = source.indexOf('libc::openat(');
  assert.ok(preflight >= 0 && call > preflight && locked > call,
    'acquire must validate and pin a directory before taking the advisory lock');
  assert.ok(directory > locked && openat > directory,
    'helper must open a no-follow directory descriptor before resolving the lock leaf');
  assert.match(source, /directory\.as_raw_fd\(\)/);
  assert.match(source, /metadata\.uid\(\)/);
  assert.match(source, /metadata\.mode\(\) & 0o022/);
  assert.match(source, /fn refuses_symlinked_containing_directory_without_creating_lock/);
  assert.match(source, /fn refuses_group_writable_containing_directory_before_lock_creation/);
  assert.match(source, /\.nlink\(\)\s*!= 1/);
  assert.match(source, /file\.try_lock\(\)/);
  assert.match(source, /fn refuses_private_hardlink_to_another_file/);
  assert.match(source, /fn refuses_symlink_leaf_after_metadata_preflight/);
});

test('file read tool validates opened leaf FD and bounded bytes in anchored traversal (#94)', async () => {
  const source = await readFile('src-tauri/src/tools/pinned_read.rs', 'utf8');
  const registry = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  assert.match(source, /fn read_scoped_file\(root: &File, relative: &Path\)/);
  assert.match(source, /libc::O_RDONLY \| libc::O_NOFOLLOW \| libc::O_CLOEXEC \| extra_flags/);
  assert.match(source, /let metadata = file\s*\.metadata\(\)/);
  assert.match(source, /metadata\.nlink\(\) != 1/);
  assert.match(source, /file\.take\(MAX_FILE_BYTES \+ 1\)/);
  assert.match(source, /Component::Normal\(name\)/);
  assert.match(registry, /spawn_blocking\(move \|\| \{/);
  assert.match(registry, /crate::tools::pinned_read::read_scoped_file\(fd, relative\)/);
  assert.match(registry, /Self::scoped_read_with_lease\(&roots, &read_path,/);
  assert.match(source, /fn preserves_leaf_type_nlink_utf8_and_64k_limit/);
  assert.match(source, /fn rejects_absolute_parent_and_symlinked_intermediate_components/);
  assert.doesNotMatch(registry, /tokio::fs::read\(&path\)/);
  assert.doesNotMatch(registry, /tokio::fs::metadata\(&path\)/);
});

test('bash tool streams and caps both pipes before producing JSON (#91)', async () => {
  const source = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const manifest = await readFile('src-tauri/Cargo.toml', 'utf8');
  assert.match(source, /async fn read_bounded_output/);
  assert.match(source, /Vec::with_capacity\(MAX_SHELL_OUTPUT\)/);
  assert.match(source, /let remaining = MAX_SHELL_OUTPUT\.saturating_sub\(retained\.len\(\)\)/);
  assert.match(source, /\.stdout\(Stdio::piped\(\)\)/);
  assert.match(source, /\.stderr\(Stdio::piped\(\)\)/);
  assert.match(source, /tokio::try_join!\([\s\S]*read_bounded_output\(stdout\)[\s\S]*read_bounded_output\(stderr\)/);
  assert.match(source, /"output_truncated": stdout\.1 \|\| stderr\.1/);
  assert.match(source, /fn stdout_and_stderr_drains_are_bounded_without_deadlock/);
  assert.match(source, /fn output_truncation_detects_exact_byte_boundary/);
  assert.doesNotMatch(source, /process\.output\(\)/);
  assert.match(manifest, /"io-util"/);
  assert.match(source, /kill_on_drop\(true\)/);
});

test('failed persisted root-grant change leaves live registry and UI in sync (#117)', async () => {
  const source = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  assert.match(source, /fn persist_root_grants\(/);
  assert.match(source, /let mut staged = settings\.clone\(\)/);
  assert.match(source, /registry\.commit_roots_transaction\(roots, \|\| \{[\s\S]*?persist\(&staged\)\.map_err/);
  assert.match(source, /registry\.commit_roots_transaction\(roots, \|\| \{/);
  assert.match(source, /persist\(&staged\)\.map_err\(\|_\| "Cannot persist approved roots"\.to_owned\(\)\)/);
  assert.match(source, /\}\)\?;\s*\*settings = staged/);
  assert.doesNotMatch(source, /persist\(&staged\)\.map_err\([^\n]+\)\?;\s*registry\.set_roots/);
  // The native serialized helper now carries the production save callback
  // through the root-mutation mutex; do not demand direct calls from the UI.
  assert.match(source, /persist_root_grants\(\s*&mut settings,\s*&state\.registry,\s*resolved,\s*persist\s*\)/);
  assert.match(source, /commit_serialized_roots\(\s*&\*state,\s*roots,[\s\S]*?AgentSettings::save,\s*\)/);
  assert.match(source, /fn failed_grant_write_preserves_live_authorization_and_in_memory_settings/);
  assert.match(source, /fn successful_grant_write_replaces_live_roots_without_partial_state/);
});

test('poisoned registry fails closed before disk persistence and never panics in read authorization (#171)', async () => {
  const source = await readFile('src-tauri/src/tools/registry.rs', 'utf8');
  const commits = await readFile('src-tauri/src/tools/commands.rs', 'utf8');
  const mutation = source.slice(source.indexOf('pub(crate) fn commit_roots_transaction('),
    source.indexOf('pub fn set_roots('));
  const writer = mutation.indexOf('.write()');
  const save = mutation.indexOf('persist()?');
  const publish = mutation.indexOf('*current = roots');
  assert.ok(writer >= 0 && save > writer && publish > save,
    'healthy registry writer must be acquired before durable save and live publication');
  assert.match(mutation, /map_err\(\|_\| "Directory permission registry unavailable"/);
  assert.match(source, /fn poisoned_root_registry_fails_closed_without_panicking_or_saving/);
  assert.match(commits, /fn poisoned_registry_writer_denies_root_save_before_any_disk_change/);
  const lease = source.slice(source.indexOf('fn scoped_read_with_lease<T>('),
    source.indexOf('fn allowed_path('));
  assert.match(lease, /\.read\(\)\s*\.map_err\(\|_\| "Directory permission registry unavailable"/);
  const auth = source.slice(source.indexOf('fn allowed_path('), source.indexOf('fn reauthorize_after_approval('));
  assert.match(auth, /\.read\(\)\s*\.map_err\(\|_\| "Directory permission registry unavailable"/);
  assert.doesNotMatch(mutation, /expect\(|unwrap\(/);
  assert.doesNotMatch(lease, /expect\("roots lock poisoned"\)/);
});
