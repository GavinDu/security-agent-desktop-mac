/**
 * Read-only native macOS listener evidence for physical Foundation acceptance.
 * Never print lsof raw output, PIDs, usernames, root paths or credentials.
 */
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
const run = promisify(execFile);

export function parseListenerNames(output) {
  if (typeof output !== 'string' || output.length > 16384) {
    throw new Error('Native listener metadata is unavailable');
  }
  // -F n prints one "n" network-name field per socket (other fields ignored).
  // No raw field value is ever included in an exception or success message.
  return output.split(/\r?\n/).filter((line) => line.startsWith('n'))
    .map((line) => line.slice(1));
}

export function assertListenerState(output, afterQuit = false) {
  const names = parseListenerNames(output);
  if (afterQuit) {
    if (names.length !== 0) {
      throw new Error('TCP 8080 listener remains after desktop Quit');
    }
    return { listenerCount: 0, state: 'stopped' };
  }
  // Require a single literal IPv4 loopback socket. Never trust a server
  // self-reported health.bind property as proof of an OS-level bind.
  if (names.length !== 1 || names[0] !== '127.0.0.1:8080') {
    throw new Error('TCP 8080 is not a single IPv4 loopback-only listener');
  }
  return { listenerCount: 1, state: 'loopback-only' };
}

export async function inspectMacListener(afterQuit = false, platform = process.platform,
                                          execute = run) {
  if (platform !== 'darwin') {
    throw new Error('Native TCP listener audit requires macOS');
  }
  let stdout;
  try {
    ({ stdout } = await execute('lsof',
      ['-nP', '-iTCP:8080', '-sTCP:LISTEN', '-F', 'n'],
      { timeout: 5000, maxBuffer: 16384 }));
  } catch (error) {
    // lsof exits 1 with no output when no listener matches. Every other
    // failure (including permission denial) must not look like clean Quit.
    if (error.code === 1 && !error.killed &&
        !(error.stdout || '').trim() && !(error.stderr || '').trim()) {
      stdout = '';
    } else {
      throw new Error('Cannot safely inspect the native TCP listener');
    }
  }
  return assertListenerState(stdout, afterQuit);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const args = process.argv.slice(2);
  if (args.length > 1 || (args.length === 1 && args[0] !== '--after-quit')) {
    process.stderr.write('FAIL: use --after-quit after the tray Quit action.\n');
    process.exitCode = 2;
  } else {
    inspectMacListener(args.includes('--after-quit')).then((value) => {
      process.stdout.write('PASS: native TCP listener ' + value.state +
        ', count=' + value.listenerCount + '\n');
    }).catch((error) => {
      process.stderr.write('FAIL: ' + error.message + '\n');
      process.exitCode = 1;
    });
  }
}
