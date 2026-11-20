import { listen } from '@tauri-apps/api/event';
import { connectorBridge, type ApprovalEvent } from '../bridges/connectors';

const el = (id: string): HTMLElement => {
  const element = document.getElementById(id);
  if (!element) throw new Error('Missing element: ' + id);
  return element;
};
const allow = el('allow') as HTMLButtonElement;
const deny = el('deny') as HTMLButtonElement;
let pending: ApprovalEvent | null = null;

async function refresh(): Promise<void> {
  try {
    const [status, tools] = await Promise.all([connectorBridge.status(), connectorBridge.list()]);
    el('status').textContent = 'Running';
    el('status').classList.add('ok');
    el('binding').textContent = 'Listening on ' + status.binding + (status.vpn_active ? ' · VPN' : ' · loopback only');
    el('tools').textContent = JSON.stringify(tools, null, 2);
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

el('refresh').addEventListener('click', () => void refresh());
allow.addEventListener('click', () => void respond(true));
deny.addEventListener('click', () => void respond(false));

void listen<ApprovalEvent>('security-agent://tool-approval', (event) => {
  pending = event.payload;
  el('approval-text').textContent = pending.tool + ': ' + pending.preview;
  allow.disabled = false;
  deny.disabled = false;
});
void refresh();
