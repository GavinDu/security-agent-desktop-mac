/**
 * Read-only, operator-safe audit of the local desktop settings file.
 * Never return root names or leak filesystem paths in errors.
 * Imported by smoke-local.mjs and independently tested in CI.
 */
import { lstat, readFile, stat } from 'node:fs/promises';
import { isAbsolute } from 'node:path';

class SafeAuditError extends Error {}

const fail = (message) => { throw new SafeAuditError(message); };

export async function auditSavedSettings(file) {
  try {
    let metadata;
    try {
      metadata = await lstat(file);
    } catch (error) {
      if (error?.code === 'ENOENT') {
        return { saved: false, rootCount: 0, policyCount: 0 };
      }
      fail('Cannot read saved settings metadata.');
    }

    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      fail('Saved settings must be a regular file, not a symlink.');
    }
    if ((metadata.mode & 0o777) !== 0o600) {
      fail('Saved settings must have private 0600 file permissions.');
    }

    let parsed;
    try {
      parsed = JSON.parse(await readFile(file, 'utf8'));
    } catch {
      fail('Saved settings JSON is unreadable or invalid.');
    }
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
      if (!directory.isDirectory()) {
        fail('A configured root is not a directory.');
      }
    }

    return { saved: true, rootCount: roots.length, policyCount: Object.keys(policies).length };
  } catch (error) {
    // Sanitized messages are the only data we propagate. fs/JSON exceptions
    // can contain the user's home directory or one of their private roots.
    if (error instanceof SafeAuditError) throw error;
    throw new SafeAuditError('Cannot audit saved settings or granted directories.');
  }
}
