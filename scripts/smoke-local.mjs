/**
 * CLI smoke test for a *running* Mac desktop app.
 * No API token is printed, passed as a CLI argument, or stored in a file.
 * `npm run smoke` runs unauthenticated checks on all platforms.
 * `npm run smoke -- --authenticated` additionally reads only this app's
 * API token from the current user's macOS Keychain.
 */
import assert from 'node:assert/strict';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { auditSavedSettings } from './smoke-settings.mjs';
import { readAgentApiToken } from './smoke-keychain.mjs';

const base = 'http://127.0.0.1:8080';
const options = { redirect: 'error' };

async function request(path, authorization) {
  return fetch(new URL(path, base), {
    ...options,
    signal: AbortSignal.timeout(4000),
    headers: authorization ? { Authorization: `Bearer ${authorization}` } : {},
  });
}

async function main() {
  const authenticated = process.argv.includes('--authenticated');
  const health = await request('/health');
  assert.equal(health.status, 200, 'local health must be available');
  const payload = await health.json();
  assert.equal(payload.ok, true);
  assert.equal(payload.binding, '127.0.0.1:8080',
    'refuse to smoke-test an unexpected LAN or tunnel bind');

  assert.equal((await request('/tools')).status, 401, '/tools must be authenticated');
  assert.equal((await request('/pairing')).status, 401, '/pairing must be authenticated');

  if (authenticated) {
    const apiToken = await readAgentApiToken();
    const tools = await request('/tools', apiToken);
    assert.equal(tools.status, 200);
    const catalog = await tools.json();
    assert.ok(Array.isArray(catalog.tools), 'tools must contain a JSON array');
    assert.ok(catalog.tools.some(({ function: fn }) => fn?.name === 'filesystem__read_file'));
    assert.ok(catalog.tools.some(({ function: fn }) => fn?.name === 'bash__run'));
    assert.equal((await request('/pairing', apiToken)).status, 501,
      'QR pairing must stay explicitly unavailable until implemented');

    const settingsFile = join(homedir(), 'Library/Application Support',
      'com.gavindu.securityagent.desktop', 'settings.json');
    const audit = await auditSavedSettings(settingsFile);
    process.stdout.write(`PASS: local settings saved=${audit.saved}, root grants=${audit.rootCount}, policies=${audit.policyCount}\n`);
  }
  process.stdout.write(`PASS: local health, 401 security gates${authenticated ? ', Keychain tool catalog, root-grant audit and 501 pairing' : ''}\n`);
}

main().catch((error) => {
  process.stderr.write(`FAIL: ${error.message}\nStart the app with npm run dev, then run npm run smoke [-- --authenticated].\n`);
  process.exitCode = 1;
});
