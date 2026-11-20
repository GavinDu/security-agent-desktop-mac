import { listen } from '@tauri-apps/api/event';
import { connectorBridge, type ApprovalEvent } from '../bridges/connectors';

const el = (id: string): HTMLElement => {
  const element = document.getElementById(id);
  if (!element) throw new Error('Missing element: ' + id);
  return element;
};
const allow = el('allow') as HTMLButtonElement;
const deny = el('deny') as HTMLButtonElement;
const rootInput = el('rootPath') as HTMLInputElement;
const bashPolicy = el('bashPolicy') as HTMLSelectElement;
let pending: ApprovalEvent | null = null;
let configuredRoots: string[] = [];

async function refresh(): Promise<void> {
  try {
    const [status, tools, settings] = await Promise.all([
      connectorBridge.status(), connectorBridge.list(), connectorBridge.settings()
    ]);
    el('status').textContent = status.online ? 'Running' : status.error ? 'Unavailable' : 'Starting';
    el('status').classList.toggle('ok', status.online);
    el('binding').textContent = 'Configured ' + status.binding +
      (status.online ? ' · accepting connections' : status.error ? ' · ' + status.error : ' · not listening');
    el('tools').textContent = JSON.stringify(tools, null, 2);
    configuredRoots = settings.allowed_roots;
    el('roots').textContent = configuredRoots.length ? configuredRoots.join('\n') : 'No directories granted.';
    bashPolicy.value = settings.policies['bash__run'] || 'ask';
  } catch (error) {
    el('status').textContent = 'Unavailable';
    el('binding').textContent = String(error);
  }
}

async function respond(approved: boolean): Promise<void> {
  const current = pending;
  if (!current) return;
  allow.disabled = true;
  deny.disabled = true;
  try {
    await connectorBridge.respondApproval(current.id, approved);
    if (pending?.id === current.id) {
      pending = null;
      el('approval-text').textContent = approved ? 'Approved once.' : 'Denied.';
    }
  } catch (error) {
    el('approval-text').textContent = 'Approval failed: ' + String(error);
  }
}

async function updateRoots(roots: string[]): Promise<void> {
  try {
    await connectorBridge.setAllowedRoots(roots);
    rootInput.value = '';
    el('settingsNotice').textContent = 'Directory permissions updated.';
    await refresh();
  } catch (error) {
    el('settingsNotice').textContent = 'Cannot change roots: ' + String(error);
  }
}

el('refresh').addEventListener('click', () => void refresh());
el('previewPeer').addEventListener('click', () => {
  const publicKey = (el('peerKey') as HTMLInputElement).value.trim();
  const tunnelIp = (el('peerIp') as HTMLInputElement).value.trim();
  void connectorBridge.previewWireGuardPeer(publicKey, tunnelIp)
    .then((config) => { el('peerPreview').textContent = config; })
    .catch((error: unknown) => { el('peerPreview').textContent = 'Validation error: ' + String(error); });
});
allow.addEventListener('click', () => void respond(true));
deny.addEventListener('click', () => void respond(false));
el('grantRoot').addEventListener('click', () => {
  const root = rootInput.value.trim();
  if (root) void updateRoots([...configuredRoots, root]);
});
el('clearRoots').addEventListener('click', () => void updateRoots([]));
bashPolicy.addEventListener('change', () => {
  const policy = bashPolicy.value as 'auto' | 'ask' | 'disable';
  if (policy === 'auto' && !window.confirm('Auto-approve lets remote tools run arbitrary shell commands. Enable anyway?')) {
    bashPolicy.value = 'ask';
    return;
  }
  void connectorBridge.setPolicy('bash__run', policy)
    .then(() => { el('settingsNotice').textContent = 'Shell policy updated.'; })
    .catch((error: unknown) => { el('settingsNotice').textContent = String(error); void refresh(); });
});
void listen<ApprovalEvent>('security-agent://tool-approval', (event) => {
  pending = event.payload;
  el('approval-text').textContent = pending.tool + ': ' + pending.preview;
  allow.disabled = false;
  deny.disabled = false;
});
void refresh();
