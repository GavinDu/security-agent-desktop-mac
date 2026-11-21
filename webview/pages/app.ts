import { listen } from '@tauri-apps/api/event';
import { connectorBridge, type ApprovalEvent } from '../bridges/connectors';
import { PolicyWriteCoordinator, type ShellPolicy } from '../bridges/policy-write';
import { ApprovalReplyCoordinator } from '../bridges/approval-reply';

const el = (id: string): HTMLElement => {
  const element = document.getElementById(id);
  if (!element) throw new Error('Missing element: ' + id);
  return element;
};
const allow = el('allow') as HTMLButtonElement;
const deny = el('deny') as HTMLButtonElement;
const rootInput = el('rootPath') as HTMLInputElement;
const grantRootButton = el('grantRoot') as HTMLButtonElement;
const clearRootsButton = el('clearRoots') as HTMLButtonElement;
const bashPolicy = el('bashPolicy') as HTMLSelectElement;
let pending: ApprovalEvent | null = null;
const approvalReplies = new ApprovalReplyCoordinator();
let configuredRoots: string[] = [];
// Never display a speculative change as an acknowledged permission state.
const policyWrites = new PolicyWriteCoordinator();
let confirmedBashPolicy: ShellPolicy | null = null;
let policyEpoch = 0;
// Prevent overlapping owner root grant/revocation IPC writes from this WebView.
let rootsWriteInFlight = false;
bashPolicy.disabled = true;

type AgentStatus = Awaited<ReturnType<typeof connectorBridge.status>>;

function renderStatus(status: AgentStatus): void {
  el('status').textContent = status.online ? 'Running' : status.error ? 'Unavailable' : 'Starting';
  el('status').classList.toggle('ok', status.online);
  el('binding').textContent = 'Configured ' + status.binding +
    (status.online ? ' · accepting connections' : status.error ? ' · ' + status.error : ' · not listening');
}

async function refreshStatus(): Promise<void> {
  try {
    renderStatus(await connectorBridge.status());
  } catch {
    el('status').textContent = 'Unavailable';
    el('status').classList.remove('ok');
    el('binding').textContent = 'Local agent status could not be retrieved.';
  }
}

async function refresh(): Promise<void> {
  const epoch = policyEpoch;
  try {
    const [status, tools, settings] = await Promise.all([
      connectorBridge.status(), connectorBridge.list(), connectorBridge.settings()
    ]);
    renderStatus(status);
    el('tools').textContent = JSON.stringify(tools, null, 2);
    configuredRoots = settings.allowed_roots;
    el('roots').textContent = configuredRoots.length ? configuredRoots.join('\n') : 'No directories granted.';
    // A refresh begun before a policy save must not publish stale state.
    if (epoch === policyEpoch && !policyWrites.inFlight) {
      confirmedBashPolicy = settings.policies['bash__run'] || 'ask';
      bashPolicy.value = confirmedBashPolicy;
      bashPolicy.disabled = false;
    }
  } catch (error) {
    el('status').textContent = 'Unavailable';
    el('binding').textContent = 'Local agent settings could not be retrieved.';
  }
}

async function respond(approved: boolean): Promise<void> {
  const current = pending;
  if (!current || approvalReplies.inFlight) return;
  allow.disabled = true;
  deny.disabled = true;
  try {
    const result = await approvalReplies.tryRespond(
      current.id, approved, connectorBridge.respondApproval
    );
    // An older reply must never erase a newer approval event.
    if (pending?.id !== current.id) return;
    if (result === 'accepted') {
      pending = null;
      el('approval-text').textContent = approved ? 'Approved once.' : 'Denied.';
    } else if (result === 'expired') {
      pending = null;
      el('approval-text').textContent = 'Approval expired or no longer pending.';
    }
  } catch {
    // Do not interpolate arbitrary native/IPC error messages or claim a
    // permission was granted when the backend reply was not acknowledged.
    if (pending?.id === current.id) {
      el('approval-text').textContent = 'Approval response failed; retry or deny.';
    }
  } finally {
    // On IPC error, the same outstanding request may be retried. If a new
    // event arrived while waiting, only that new request may be answered.
    allow.disabled = !pending;
    deny.disabled = !pending;
  }
}

async function updateRoots(roots: string[]): Promise<void> {
  // Native validation can take longer for one directory than another.
  // Never let two user actions from this window race to commit grants.
  if (rootsWriteInFlight) return;
  rootsWriteInFlight = true;
  grantRootButton.disabled = true;
  clearRootsButton.disabled = true;
  el('settingsNotice').textContent = 'Updating directory permissions...';
  try {
    await connectorBridge.setAllowedRoots(roots);
    rootInput.value = '';
    el('settingsNotice').textContent = 'Directory permissions updated.';
    await refresh();
  } catch {
    // IPC errors may carry paths; do not reflect private native details.
    el('settingsNotice').textContent =
      'Directory permissions could not be changed. Previous confirmed permissions remain in effect.';
  } finally {
    rootsWriteInFlight = false;
    grantRootButton.disabled = false;
    clearRootsButton.disabled = false;
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
grantRootButton.addEventListener('click', () => {
  const root = rootInput.value.trim();
  if (root) void updateRoots([...configuredRoots, root]);
});
clearRootsButton.addEventListener('click', () => void updateRoots([]));
async function saveBashPolicy(): Promise<void> {
  const requested = bashPolicy.value as ShellPolicy;
  if (confirmedBashPolicy === null || policyWrites.inFlight) {
    bashPolicy.value = confirmedBashPolicy ?? 'ask';
    return;
  }
  // Show only the last acknowledged mode while the write is pending.
  bashPolicy.value = confirmedBashPolicy;
  if (requested === confirmedBashPolicy) return;
  if (requested === 'auto' &&
      !window.confirm('Auto-approve lets remote tools run arbitrary shell commands. Enable anyway?')) {
    return;
  }

  policyEpoch += 1;
  bashPolicy.disabled = true;
  el('settingsNotice').textContent = 'Updating shell policy...';
  try {
    const saved = await policyWrites.tryWrite(requested,
      (policy) => connectorBridge.setPolicy('bash__run', policy));
    if (!saved) throw new Error('Policy write in progress');
    confirmedBashPolicy = requested;
    bashPolicy.value = requested;
    el('settingsNotice').textContent = 'Shell policy updated.';
  } catch {
    // Never interpret a failed Tauri invoke as successful policy revocation.
    bashPolicy.value = confirmedBashPolicy;
    el('settingsNotice').textContent =
      'Shell policy update failed; previous confirmed setting retained.';
  } finally {
    policyEpoch += 1;
    bashPolicy.disabled = false;
  }
}
bashPolicy.addEventListener('change', () => void saveBashPolicy());
void listen<ApprovalEvent>('security-agent://tool-approval', (event) => {
  pending = event.payload;
  el('approval-text').textContent = pending.tool + ': ' + pending.preview;
  allow.disabled = approvalReplies.inFlight;
  deny.disabled = approvalReplies.inFlight;
});
void refresh();
// Status polling must not overwrite a user's in-progress permissions edits.
// Keep this independent of the full settings/catalog refresh.
window.setInterval(() => void refreshStatus(), 5000);
