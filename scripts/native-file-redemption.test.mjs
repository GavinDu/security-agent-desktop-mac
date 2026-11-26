import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { transformSync } from 'esbuild';

const source = readFileSync('webview/bridges/native-file.ts', 'utf8');
const { code } = transformSync(source, { loader: 'ts', format: 'esm' });
const { redeemNativeFile } = await import('data:text/javascript;base64,' + Buffer.from(code).toString('base64'));
const ticket = '00000000-0000-4000-8000-000000000001';
const denied = { message: 'File read authorization changed' };

test('native file redemption sends only a canonical ticket in a credential-free POST', async () => {
  let calls = 0;
  const result = await redeemNativeFile(async () => ticket, async (url, init) => {
    calls++;
    assert.equal(url, 'security-agent-file://localhost/redeem');
    assert.equal(init.method, 'POST');
    assert.equal(init.credentials, 'omit');
    assert.equal(init.cache, 'no-store');
    assert.deepEqual(init.headers, { 'Content-Type': 'text/plain' });
    assert.equal(init.body, ticket);
    return new Response(JSON.stringify({ path: '/fixture', content: 'x'.repeat(65536) }));
  });
  assert.equal(calls, 1);
  assert.equal(result.content.length, 65536);
});

test('malformed tickets never reach native transport', async () => {
  for (const value of [null, {}, '', ticket + '\n', ticket + '?x=1', 'A'.repeat(36)]) {
    await assert.rejects(redeemNativeFile(async () => value, async () => {
      assert.fail('malformed ticket dispatched');
    }), denied);
  }
});

test('denial, malformed response and transport failure are fixed and never retried', async () => {
  for (const fetcher of [
    async () => new Response('private path or bytes', { status: 403 }),
    async () => new Response(JSON.stringify({ error: '/private/path' })),
    async () => { throw new Error('private native diagnostic'); },
  ]) {
    let calls = 0;
    await assert.rejects(redeemNativeFile(async () => ticket, async (...args) => {
      calls++;
      return fetcher(...args);
    }), denied);
    assert.equal(calls, 1);
  }
});

test('aborted preparation cannot dispatch a ticket and aborted response cannot return bytes', async () => {
  const before = new AbortController();
  before.abort();
  await assert.rejects(redeemNativeFile(async () => {
    assert.fail('aborted preparation invoked');
  }, async () => assert.fail('aborted fetch'), before.signal), denied);

  const during = new AbortController();
  await assert.rejects(redeemNativeFile(async () => {
    during.abort();
    return ticket;
  }, async () => assert.fail('aborted fetch'), during.signal), denied);

  const after = new AbortController();
  await assert.rejects(redeemNativeFile(async () => ticket, async (_url, init) => {
    assert.equal(init.signal, after.signal);
    return {
      ok: true,
      json: async () => {
        after.abort();
        return { path: '/fixture', content: 'must not return' };
      },
    };
  }, after.signal), denied);
});
