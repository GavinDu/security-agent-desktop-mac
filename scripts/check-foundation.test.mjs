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
    ['src-tauri/src/tools/commands.rs', 7],
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
    await assert.rejects(auditSavedSettings(file), /not a symlink/);
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
  const flags = source.indexOf('.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)');
  const open = source.indexOf('.open(path)');
  assert.ok(preflight >= 0 && flags > preflight && open > flags,
    'kernel no-follow flags must be present on the descriptor open');
  assert.match(source, /\.nlink\(\)\s*!= 1/);
  assert.match(source, /file\.try_lock\(\)/);
  assert.match(source, /fn refuses_private_hardlink_to_another_file/);
  assert.match(source, /fn refuses_symlink_leaf_after_metadata_preflight/);
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
