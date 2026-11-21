/**
 * Read-only, operator-invoked macOS Keychain helper for the local smoke test.
 * Return the token solely to the in-process authenticated fetch caller.
 * Never log stdout/stderr, home paths, token bytes or shell commands.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
const run = promisify(execFile);

export async function readAgentApiToken(platform = process.platform, execute = run) {
  if (platform !== 'darwin') {
    throw new Error('Authenticated smoke requires macOS Keychain');
  }
  let stdout;
  try {
    ({ stdout } = await execute('/usr/bin/security', [
      'find-generic-password', '-s', 'com.gavindu.securityagent.desktop',
      '-a', 'agent-api-token', '-w',
    ], { maxBuffer: 2048, timeout: 4000, encoding: 'utf8' }));
  } catch {
    throw new Error('Application Keychain token unavailable for the active login');
  }
  if (typeof stdout !== 'string') {
    throw new Error('Application Keychain token is missing or invalid');
  }
  // The security CLI normally appends one line ending. Do not trim arbitrary
  // whitespace: multiple lines, control characters or spaces must be rejected.
  const token = stdout.replace(/\r?\n$/, '');
  if (token.length < 32 || token.length > 512 ||
      !/^[\x21-\x7e]+$/.test(token)) {
    throw new Error('Application Keychain token is missing or invalid');
  }
  return token;
}
