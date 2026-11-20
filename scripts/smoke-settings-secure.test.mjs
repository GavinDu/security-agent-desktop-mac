import test from 'node:test';
import assert from 'node:assert/strict';
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { auditSavedSettings } from './smoke-settings.mjs';

async function fixture(fn) {
  const root = await mkdtemp(join(tmpdir(), 'desktop-smoke-fd-'));
  const file = join(root, 'settings.json');
  const granted = join(root, 'private-grant');
  try {
    await mkdir(granted);
    const valid = { allowed_roots: [granted], policies: { bash__run: 'ask' } };
    const save = async (data) => {
      await writeFile(file, typeof data === 'string' || Buffer.isBuffer(data)
        ? data : JSON.stringify(data));
      await chmod(file, 0o600);
    };
    await fn({ root, file, granted, valid, save });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test('one-descriptor audit handles missing and valid private settings without disclosing roots', async () => {
  await fixture(async ({ file, granted, valid, save }) => {
    assert.deepEqual(await auditSavedSettings(file),
      { saved: false, rootCount: 0, policyCount: 0 });
    await save(valid);
    const counts = await auditSavedSettings(file);
    assert.deepEqual(counts, { saved: true, rootCount: 1, policyCount: 1 });
    assert.ok(!JSON.stringify(counts).includes(granted));
  });
});

test('one-descriptor audit rejects symlink and hardlink leaves', async () => {
  await fixture(async ({ root, file, valid, save }) => {
    await save(valid);
    const linkFile = join(root, 'linked.json');
    await link(file, linkFile);
    await assert.rejects(auditSavedSettings(file), /hard links/);
    await rm(linkFile);
    await rm(file);
    await symlink(join(root, 'missing-target'), file);
    await assert.rejects(auditSavedSettings(file), /Cannot safely open/);
    await rm(file);
    await save(valid);
    await rm(file);
    await symlink(join(root, 'real-settings.json'), file);
    await assert.rejects(auditSavedSettings(file), /Cannot safely open/);
  });
});

test('one-descriptor audit rejects public mode and more than 256 KiB', async () => {
  await fixture(async ({ file, valid, save }) => {
    await save(valid);
    await chmod(file, 0o644);
    await assert.rejects(auditSavedSettings(file), /private 0600/);
    await save(' '.repeat(256 * 1024 + 1));
    await assert.rejects(auditSavedSettings(file), /exceeds 256 KiB/);
    await save(' '.repeat(256 * 1024));
    await assert.rejects(auditSavedSettings(file), /JSON is unreadable or invalid/);
  });
});

test('one-descriptor audit rejects invalid UTF-8 and sanitizes errors', async () => {
  await fixture(async ({ root, file, save }) => {
    await save(Buffer.from([0xff, 0xfe]));
    await assert.rejects(auditSavedSettings(file), error => {
      assert.match(error.message, /JSON is unreadable or invalid/);
      assert.ok(!error.message.includes(root));
      return true;
    });
  });
});
