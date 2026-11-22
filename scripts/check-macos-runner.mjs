/**
 * Mandatory native CI admission guard. Repo variables may choose an image,
 * but never waive the ARM64 macOS 15+ release requirement.
 * Avoid printing runner-controlled values or untrusted process errors.
 */
import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

const APPROVED_RUNNERS = new Set(['macos-latest', 'macos-26', 'macos-15', 'xcode-27']);

export function validateMacosRunner({ label, runnerOs, runnerArch, version }) {
  if (!APPROVED_RUNNERS.has(label)) throw new Error('Unsupported native macOS runner label');
  if (runnerOs !== 'macOS' || runnerArch !== 'ARM64') {
    throw new Error('Native macOS runner must be Apple Silicon ARM64');
  }
  const match = /^(\d+)\.(\d+)(?:\.(\d+))?$/.exec(version);
  if (!match || Number(match[1]) < 15) {
    throw new Error('Native macOS runner must report macOS 15 or newer');
  }
  return { label, version, architecture: 'ARM64' };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const version = execFileSync('/usr/bin/sw_vers', ['-productVersion'], {
      encoding: 'utf8', timeout: 5000, maxBuffer: 1024,
    }).trim();
    const host = validateMacosRunner({
      label: process.env.SELECTED_MACOS_RUNNER,
      runnerOs: process.env.RUNNER_OS,
      runnerArch: process.env.RUNNER_ARCH,
      version,
    });
    process.stdout.write('Validated native runner: ' + host.label +
      ', macOS ' + host.version + ', ARM64\n');
  } catch {
    process.stderr.write('::error::Native runner must be approved macOS 15+ ARM64\n');
    process.exitCode = 1;
  }
}
