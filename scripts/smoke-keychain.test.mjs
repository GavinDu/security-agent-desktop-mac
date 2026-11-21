import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { readAgentApiToken } from './smoke-keychain.mjs';

const token = 'a'.repeat(42) + '_';

test('native Keychain lookup uses fixed /usr/bin/security and in-process only token', async () => {
  let count = 0;
  const result = await readAgentApiToken('darwin', async (binary, args, options) => {
    count++;
    assert.equal(binary, '/usr/bin/security');
    assert.deepEqual(args, [
      'find-generic-password', '-s', 'com.gavindu.securityagent.desktop',
      '-a', 'agent-api-token', '-w',
    ]);
    assert.deepEqual(options, { maxBuffer: 2048, timeout: 4000, encoding: 'utf8' });
    return { stdout: token + '\n', stderr: '' };
  });
  assert.equal(count, 1);
  assert.equal(result, token);
});

test('non-macOS helper must reject before invoking any OS command', async () => {
  let called = false;
  await assert.rejects(readAgentApiToken('linux', () => {
    called = true;
  }), /requires macOS Keychain/);
  assert.equal(called, false);
});

test('stdout data is never included in sanitized errors', async () => {
  const canary = 'never-print-keychain-' + 'Z'.repeat(40);
  const bad = ['', 'x'.repeat(31), 'x'.repeat(513), 'x'.repeat(40) + ' y',
    canary + '\nanother-token', canary + '\u0000', canary + '\rmalformed',
    canary + '\n\n', canary + '\nmore'];
  for (const output of bad) {
    await assert.rejects(readAgentApiToken('darwin', async () => ({ stdout: output })),
      (error) => {
        assert.equal(error.message, 'Application Keychain token is missing or invalid');
        assert.ok(!error.message.includes(canary));
        return true;
      });
  }
});

test('subprocess failures do not expose stdout/stderr, paths or credential values', async () => {
  const secret = 'sensitive-token-' + 'X'.repeat(38);
  for (const payload of [
    { code: 1, stderr: secret, stdout: secret },
    { message: secret },
    { killed: true, stderr: secret },
  ]) {
    await assert.rejects(readAgentApiToken('darwin', async () => { throw payload; }),
      (error) => {
        assert.equal(error.message, 'Application Keychain token unavailable for the active login');
        assert.ok(!error.message.includes(secret));
        return true;
      });
  }
});

test('smoke script never resolves credentials through PATH or logs API token', async () => {
  const source = await readFile('scripts/smoke-local.mjs', 'utf8');
  assert.match(source, /readAgentApiToken\(\)/);
  assert.doesNotMatch(source, /execFile\('security'|spawn\('security'|console\.log\(apiToken\)/);
  assert.match(source, /request\('\/tools', apiToken\)/);
  assert.match(source, /request\('\/pairing', apiToken\)/);
});
