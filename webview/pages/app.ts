import { listen } from '@tauri-apps/api/event';
import { connectorBridge, type ApprovalEvent } from '../bridges/connectors';
import { PolicyWriteCoordinator, type ShellPolicy } from '../bridges/policy-write';
import { ApprovalReplyCoordinator } from '../bridges/approval-reply';
import { RootWriteCoordinator } from '../bridges/root-write';
import { RootSnapshotCoordinator } from '../bridges/root-snapshot';

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
const rootWrites = new RootWriteCoordinator();
// Separate root readback versioning from the bash policy epoch.
const rootSnapshots = new RootSnapshotCoordinator();
// Peer-preview freshness is separate from root-grant readback freshness.
let peerPreviewEpoch = 0;
bashPolicy.disabled = true;
grantRootButton.disabled = true;
// Clearing all roots is safe even when the current root snapshot is unknown.
clearRootsButton.disabled = false;

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
  const rootEpoch = rootSnapshots.beginRefresh();
  // Starting a new settings read invalidates an older root snapshot now,
  // not only when the Promise resolves. Clear remains available.
  grantRootButton.disabled = true;
  clearRootsButton.disabled = !rootSnapshots.canRevoke;
  try {
    const [status, tools, settings] = await Promise.all([
      connectorBridge.status(), connectorBridge.list(), connectorBridge.settings()
    ]);
    renderStatus(status);
    // Only the newest authoritative readback may define the next grant array.
    if (rootSnapshots.applyRefresh(rootEpoch, settings.allowed_roots)) {
      configuredRoots = rootSnapshots.snapshot();
      el('roots').textContent = configuredRoots.length ? configuredRoots.join('\n') : 'No directories granted.';
      grantRootButton.disabled = false;
      clearRootsButton.disabled = false;
    }
    // A refresh started before a policy save must not re-advertise a
    // capability that has since been disabled. Apply catalog and policy
    // together only when both correspond to the current acknowledged epoch.
    if (epoch === policyEpoch && !policyWrites.inFlight) {
      el('tools').textContent = JSON.stringify(tools, null, 2);
      confirmedBashPolicy = settings.policies['bash__run'] || 'ask';
      bashPolicy.value = confirmedBashPolicy;
      bashPolicy.disabled = false;
    }
  } catch {
    el('status').textContent = 'Unavailable';
    el('binding').textContent = 'Local agent settings could not be retrieved.';
    // A failure of the latest readback is not permission to reuse an old
    // root set for a later read/modify/write Grant action.
    if (rootSnapshots.failRefresh(rootEpoch)) {
      grantRootButton.disabled = true;
      clearRootsButton.disabled = !rootSnapshots.canRevoke;
      el('roots').textContent = 'Directory permissions unavailable. Retry refresh or Clear Roots.';
    }
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
  // RootSnapshotCoordinator rejects stale reads and overlapping readback,
  // while RootWriteCoordinator serializes the actual trusted IPC mutation.
  if (rootWrites.inFlight || !rootSnapshots.startMutation(roots.length === 0)) return;
  grantRootButton.disabled = true;
  clearRootsButton.disabled = true;
  el('settingsNotice').textContent = 'Updating directory permissions...';
  let persisted = false;
  try {
    const accepted = await rootWrites.tryWrite(roots, (nextRoots) =>
      connectorBridge.setAllowedRoots(nextRoots));
    if (!accepted) return;
    persisted = true;
    rootInput.value = '';
    el('settingsNotice').textContent = 'Confirming directory permissions...';
  } catch {
    // Native IPC rejection text may include sensitive paths. Do not claim
    // that the previous root set was retained until readback confirms it.
    el('settingsNotice').textContent =
      'Directory permission update was not acknowledged. Checking current permissions.';
  } finally {
    rootSnapshots.finishMutation();
    // Read back the actual state after the native call settles, successful
    // or not. A failed readback keeps both controls disabled.
    await refresh();
    grantRootButton.disabled = !rootSnapshots.canWrite;
    clearRootsButton.disabled = !rootSnapshots.canRevoke;
    if (persisted) {
      el('settingsNotice').textContent = rootSnapshots.canWrite
        ? 'Directory permissions updated.'
        : 'Directory permissions may have changed; refresh to confirm.';
    } else if (rootSnapshots.canWrite) {
      el('settingsNotice').textContent =
        'Directory permission request failed. Confirmed permissions shown.';
    }
  }
}
el('refresh').addEventListener('click', () => void refresh());
const peerKeyInput = el('peerKey') as HTMLInputElement;
const peerIpInput = el('peerIp') as HTMLInputElement;
const peerPreview = el('peerPreview');
// Editing either field invalidates a completed or in-flight preview. Epoch
// guards also reject responses arriving after a newer Preview click.
function invalidatePeerPreview(): void {
  peerPreviewEpoch += 1;
  peerPreview.textContent = 'Peer preview cleared. Validate the current inputs.';
}
peerKeyInput.addEventListener('input', invalidatePeerPreview);
peerIpInput.addEventListener('input', invalidatePeerPreview);
el('previewPeer').addEventListener('click', () => {
  const epoch = ++peerPreviewEpoch;
  const publicKey = peerKeyInput.value.trim();
  const tunnelIp = peerIpInput.value.trim();
  // Recheck the source values too: DOM values may change programmatically
  // without firing an input event, and must not resurrect an old config.
  const current = () => epoch === peerPreviewEpoch &&
    peerKeyInput.value.trim() === publicKey &&
    peerIpInput.value.trim() === tunnelIp;
  peerPreview.textContent = 'Validating peer configuration...';
  void connectorBridge.previewWireGuardPeer(publicKey, tunnelIp)
    .then((config) => {
      if (current()) peerPreview.textContent = config;
    })
    .catch(() => {
      if (current()) {
        // Never display a rejected IPC error: it may carry paths, secrets
        // or low-level backend diagnostics. No generated config is retained.
        peerPreview.textContent =
          'Peer preview unavailable. Check the public key and tunnel address.';
      }
    });
});
allow.addEventListener('click', () => void respond(true));
deny.addEventListener('click', () => void respond(false));
grantRootButton.addEventListener('click', () => {
  const root = rootInput.value.trim();
  if (root && rootSnapshots.canWrite) void updateRoots([...configuredRoots, root]);
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
  let persisted = false;
  try {
    const saved = await policyWrites.tryWrite(requested,
      (policy) => connectorBridge.setPolicy('bash__run', policy));
    if (!saved) throw new Error('Policy write in progress');
    confirmedBashPolicy = requested;
    bashPolicy.value = requested;
    el('settingsNotice').textContent = 'Shell policy updated.';
    persisted = true;
  } catch {
    // Never interpret a failed Tauri invoke as successful policy revocation.
    bashPolicy.value = confirmedBashPolicy;
    el('settingsNotice').textContent =
      'Shell policy update failed; previous confirmed setting retained.';
  } finally {
    policyEpoch += 1;
    bashPolicy.disabled = false;
  }
  // Read the backend's committed policy AND catalog after successful save,
  // never publish a speculative disable and never restore a stale snapshot.
  // Another user edit increments policyEpoch and supersedes this refresh.
  if (persisted) await refresh();
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
