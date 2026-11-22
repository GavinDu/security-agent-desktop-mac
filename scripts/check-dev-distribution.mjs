/**
 * Defense in depth: verify this repository still builds only an ad-hoc,
 * local-development DMG. This is NOT a production signing certificate audit.
 */
import { readFile, readdir } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

const deniedReleaseOperations = [
  /^\s*release\s*:/m,
  /\b(?:softprops\/action-gh-release|actions\/create-release|ncipollo\/release-action)\b/i,
  /\bgh\s+release\s+(?:create|upload|edit)\b/i,
  /\b(?:npm|cargo)\s+publish\b/i,
  /\b(?:tauri-apps\/tauri-action)\b/i,
  /\b(?:contents|packages)\s*:\s*write\b/i,
  /\b(?:goreleaser|electron-builder)\s+(?:release|publish)\b/i,
];

export function auditDevelopmentDistribution(config, capabilities, workflows, cargo) {
  if (config?.bundle?.active !== true ||
      JSON.stringify(config.bundle.targets) !== JSON.stringify(['dmg']) ||
      config.bundle.macOS?.signingIdentity !== '-' ||
      config.bundle.macOS?.entitlements !== undefined) {
    throw new Error('Development installer policy must remain ad-hoc DMG with no entitlement override');
  }
  if (config.app?.withGlobalTauri !== false ||
      config.app?.windows?.length !== 1 ||
      config.app.windows[0].label !== 'main' ||
      config.app.windows[0].create !== false) {
    throw new Error('Development distribution must have one guarded local WebView');
  }
  if (capabilities?.remote !== undefined ||
      JSON.stringify(capabilities?.windows) !== JSON.stringify(['main']) ||
      JSON.stringify([...capabilities.permissions || []].sort()) !== JSON.stringify(
        ['core:event:allow-listen', 'core:event:allow-unlisten'].sort())) {
    throw new Error('Development WebView ACL must not grant updater or remote-origin access');
  }
  if (typeof cargo !== 'string' ||
      /tauri-plugin-updater|\btauri_plugin_updater\b/i.test(cargo)) {
    throw new Error('Unsigned developer app must not enable auto-updater');
  }
  if (!Array.isArray(workflows) || workflows.length === 0) {
    throw new Error('No workflow sources were supplied for release audit');
  }
  for (const entry of workflows) {
    if (!/^[\w.-]+\.ya?ml$/.test(entry?.name || '') ||
        typeof entry?.content !== 'string') {
      throw new Error('Cannot audit workflow source');
    }
    for (const pattern of deniedReleaseOperations) {
      if (pattern.test(entry.content)) {
        throw new Error('Release/publish operation is forbidden in developer-only CI');
      }
    }
  }
  // The action's own Node runtime is independent of the app's Node 22.
  // Deny legacy Node 20 action majors in every workflow, not just the CI job.
  const node20Action = /\buses:\s*actions\/(?:checkout|setup-node)@v[1-4]\b|\buses:\s*actions\/upload-artifact@v[1-5]\b/;
  for (const entry of workflows) {
    if (node20Action.test(entry.content)) {
      throw new Error('Deprecated Node20 workflow action is forbidden');
    }
  }
  const native = workflows.find((entry) => entry.name === 'ci.yml');
  if (!native ||
      !/^    runs-on: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}$/m.test(native.content) ||
      !/SELECTED_MACOS_RUNNER: \$\{\{ vars\.MACOS_RUNNER_LABEL \|\| 'macos-latest' \}\}/.test(native.content) ||
      !/run: node scripts\/check-macos-runner\.mjs/.test(native.content) ||
      !/bash scripts\/verify-macos-bundle\.sh/.test(native.content) ||
      !/actions\/upload-artifact@v6/.test(native.content) ||
      !/name:\s*unsigned-security-agent-mac/.test(native.content)) {
    throw new Error('Required strict macOS developer artifact gate is missing');
  }
  return { distribution: 'ad-hoc-development-only', publicReleaseEnabled: false };
}

export async function auditRepositoryDistribution(read = readFile, list = readdir) {
  const config = JSON.parse(await read('src-tauri/tauri.conf.json', 'utf8'));
  const capabilities = JSON.parse(await read('src-tauri/capabilities/default.json', 'utf8'));
  const cargo = await read('src-tauri/Cargo.toml', 'utf8');
  const filenames = (await list('.github/workflows')).filter((name) => /\.ya?ml$/.test(name));
  const workflows = await Promise.all(filenames.map(async (name) => ({
    name,
    content: await read('.github/workflows/' + name, 'utf8'),
  })));
  return auditDevelopmentDistribution(config, capabilities, workflows, cargo);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  auditRepositoryDistribution().then((state) => {
    process.stdout.write('PASS: ' + state.distribution + ', public release disabled\n');
  }).catch(() => {
    // Avoid echoing untrusted workflow lines, token values or local file paths.
    process.stderr.write('FAIL: developer-only macOS distribution policy violated\n');
    process.exitCode = 1;
  });
}
