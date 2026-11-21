/**
 * Read-only, operator-safe audit of the local desktop settings file.
 * The descriptor is opened once and checked before any bytes are read.
 * Never return root names or leak filesystem paths in errors.
 */
import { constants } from 'node:fs';
import { open, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

const MAX_SETTINGS_BYTES = 256 * 1024;
class SafeAuditError extends Error {}

const fail = (message) => { throw new SafeAuditError(message); };

async function readPrivateSettings(file) {
  let handle;
  try {
    try {
      // O_NONBLOCK prevents a swapped-in FIFO from blocking open();
      // O_NOFOLLOW blocks leaf symlinks and the FD pins the checked inode.
      handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    } catch (error) {
      if (error?.code === 'ENOENT') return null;
      fail('Cannot safely open saved settings.');
    }

    const before = await handle.stat();
    if (!before.isFile()) fail('Saved settings must be a regular file.');
    if (before.nlink !== 1) fail('Saved settings must not have hard links.');
    if ((before.mode & 0o777) !== 0o600) {
      fail('Saved settings must have private 0600 file permissions.');
    }
    if (typeof process.getuid === 'function' && before.uid !== process.getuid()) {
      fail('Saved settings must be owned by the active user.');
    }
    if (before.size > MAX_SETTINGS_BYTES) fail('Saved settings exceeds 256 KiB.');

    // A bounded, position-based read handles partial reads and detects growth.
    const buffer = Buffer.alloc(MAX_SETTINGS_BYTES + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
    if (length > MAX_SETTINGS_BYTES) fail('Saved settings exceeds 256 KiB.');
    const after = await handle.stat();
    if (after.size !== before.size || after.mtimeMs !== before.mtimeMs) {
      fail('Saved settings changed during audit.');
    }

    try {
      // Node's implicit UTF-8 decoder silently replaces bad bytes; reject.
      const json = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(0, length));
      return JSON.parse(json);
    } catch {
      fail('Saved settings JSON is unreadable or invalid.');
    }
  } finally {
    await handle?.close();
  }
}

export async function auditSavedSettings(file) {
  try {
    const parsed = await readPrivateSettings(file);
    if (parsed === null) return { saved: false, rootCount: 0, policyCount: 0 };
    if (!parsed || Array.isArray(parsed) || typeof parsed !== 'object') {
      fail('Saved settings schema is invalid.');
    }
    if (Object.keys(parsed).some((key) => !['allowed_roots', 'policies'].includes(key))) {
      fail('Saved settings contains an unknown field.');
    }

    const roots = parsed.allowed_roots ?? [];
    const policies = parsed.policies ?? {};
    if (!Array.isArray(roots) ||
        !policies || Array.isArray(policies) || typeof policies !== 'object') {
      fail('Saved settings permissions schema is invalid.');
    }
    if (Object.values(policies).some((value) => !['auto', 'ask', 'disable'].includes(value))) {
      fail('Saved settings contains an invalid tool policy.');
    }

    for (const root of roots) {
      if (typeof root !== 'string' || !isAbsolute(root)) {
        fail('A configured root is not an absolute directory.');
      }
      let directory;
      try {
        directory = await stat(root);
      } catch {
        fail('A configured root is unavailable.');
      }
      if (!directory.isDirectory()) fail('A configured root is not a directory.');
    }

    return { saved: true, rootCount: roots.length, policyCount: Object.keys(policies).length };
  } catch (error) {
    // Sanitized messages are the only data we propagate. fs/JSON exceptions
    // can contain the user's home directory or one of their private roots.
    if (error instanceof SafeAuditError) throw error;
    throw new SafeAuditError('Cannot audit saved settings or granted directories.');
  }
}
