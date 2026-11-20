import test from 'node:test';
import assert from 'node:assert/strict';
import { assertListenerState, inspectMacListener, parseListenerNames } from './smoke-macos-listener.mjs';

test('parse lsof field output but never return PID or username', () => {
  assert.deepEqual(parseListenerNames('p413\ncSecurity Agent\nn127.0.0.1:8080\n'),
    ['127.0.0.1:8080']);
  assert.throws(() => parseListenerNames(null), /unavailable/);
  assert.throws(() => parseListenerNames('x'.repeat(16385)), /unavailable/);
});

test('local only: allow exactly one literal IPv4 loopback TCP listener', () => {
  assert.deepEqual(assertListenerState('p321\nn127.0.0.1:8080\n'),
    { listenerCount: 1, state: 'loopback-only' });
  for (const raw of [
    '', 'n*:8080\n', 'n0.0.0.0:8080\n', 'n192.168.1.9:8080\n',
    'n[::]:8080\n', 'n[::1]:8080\n', 'n127.0.0.1:8080\nn127.0.0.1:8080\n',
    'n127.0.0.1:8081\n', 'nlocalhost:8080\n',
  ]) {
    assert.throws(() => assertListenerState(raw), (err) => {
      assert.equal(err.message, 'TCP 8080 is not a single IPv4 loopback-only listener');
      assert.ok(!err.message.includes('192.168.1.9'));
      return true;
    });
  }
});

test('after Quit requires zero native TCP 8080 listeners', () => {
  assert.deepEqual(assertListenerState('', true), { listenerCount: 0, state: 'stopped' });
  assert.throws(() => assertListenerState('n127.0.0.1:8080\n', true), /remains/);
  assert.throws(() => assertListenerState('n0.0.0.0:8080\n', true), /remains/);
});

test('macOS OS-listener collection uses fixed read-only lsof args', async () => {
  const result = await inspectMacListener(false, 'darwin', async (command, args, options) => {
    assert.equal(command, '/usr/sbin/lsof');
    assert.deepEqual(args, ['-nP', '-iTCP:8080', '-sTCP:LISTEN', '-F', 'n']);
    assert.equal(options.timeout, 5000);
    return { stdout: 'p222\ncagent\nn127.0.0.1:8080\n' };
  });
  assert.equal(result.state, 'loopback-only');
  await assert.rejects(inspectMacListener(false, 'linux'), /requires macOS/);
});

test('lsof no-match is allowed only after quit; errors fail closed', async () => {
  const noListener = async () => {
    throw { code: 1, stdout: '', stderr: '' };
  };
  assert.deepEqual(await inspectMacListener(true, 'darwin', noListener),
    { listenerCount: 0, state: 'stopped' });
  await assert.rejects(inspectMacListener(false, 'darwin', noListener), /not a single/);
  for (const failure of [
    { code: 1, stdout: '', stderr: 'permission denied' },
    { code: 2, stdout: '', stderr: '' },
    { code: 1, stdout: 'n0.0.0.0:8080\n', stderr: '' },
    { code: 1, stdout: '', stderr: '', killed: true },
  ]) {
    await assert.rejects(inspectMacListener(true, 'darwin', async () => { throw failure; }),
      /Cannot safely inspect/);
  }
});
