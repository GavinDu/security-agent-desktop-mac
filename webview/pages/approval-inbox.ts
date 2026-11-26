import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { ApprovalInbox } from '../bridges/approval-inbox';
import { ApprovalReplyCoordinator } from '../bridges/approval-reply';
import { connectorBridge } from '../bridges/connectors';

export function mountApprovalInbox(): void {
  const select = document.getElementById('approval-select') as HTMLSelectElement;
  const preview = document.getElementById('approval-text')!;
  const notice = document.getElementById('approval-notice')!;
  const allow = document.getElementById('allow') as HTMLButtonElement;
  const deny = document.getElementById('deny') as HTMLButtonElement;
  const refreshButton = document.getElementById('approval-refresh') as HTMLButtonElement;
  const inbox = new ApprovalInbox();
  const replies = new ApprovalReplyCoordinator();
  let reading = false;
  let dirty = false;

  function render(): void {
    const entries = inbox.available ? inbox.entries : [];
    const placeholder = new Option('Select a request to review', '');
    select.replaceChildren(placeholder, ...entries.map(item =>
      new Option(item.tool + ' · ' + item.id, item.id)));
    select.value = inbox.selection;
    select.disabled = !inbox.available || inbox.busy;
    const current = inbox.current;
    preview.textContent = current
      ? current.tool + ': ' + current.preview
      : inbox.available
        ? entries.length ? 'Select a request to review its complete input.' : 'No requests awaiting approval.'
        : 'Pending approvals unavailable. Refresh to confirm.';
    allow.disabled = !current || replies.inFlight;
    deny.disabled = !current || replies.inFlight;
  }

  async function refresh(): Promise<void> {
    if (reading || inbox.busy) return;
    reading = true;
    dirty = false;
    const version = inbox.beginRead();
    // Never start another underlying IPC while this request is outstanding,
    // even if its UI deadline expires. A late response cannot restore trust.
    const timer = window.setTimeout(() => {
      inbox.failRead(version);
      render();
    }, 3000);
    try {
      const snapshot = await invoke<unknown>('list_pending_approvals');
      inbox.applyRead(version, snapshot);
    } catch {
      inbox.failRead(version);
    } finally {
      window.clearTimeout(timer);
      reading = false;
      render();
      if (dirty && !inbox.busy) void refresh();
    }
  }

  async function respond(approved: boolean): Promise<void> {
    const current = inbox.beginResponse();
    if (!current) return;
    render();
    notice.textContent = 'Waiting for native approval acknowledgment.';
    try {
      const result = await replies.tryRespond(current.id, approved, connectorBridge.respondApproval);
      notice.textContent = result === 'accepted'
        ? approved ? 'Approved once.' : 'Denied.'
        : 'Approval expired or no longer pending.';
    } catch {
      notice.textContent = 'Approval response unknown. Refresh and review again.';
    } finally {
      inbox.finishResponse();
      render();
      void refresh();
    }
  }

  select.addEventListener('change', () => {
    inbox.select(select.value);
    render();
  });
  allow.addEventListener('click', () => void respond(true));
  deny.addEventListener('click', () => void respond(false));
  refreshButton.addEventListener('click', () => {
    inbox.invalidate();
    dirty = true;
    render();
    void refresh();
  });
  // Event payload is intentionally ignored: only native readback is trusted.
  void listen('security-agent://tool-approval', () => {
    inbox.invalidate();
    dirty = true;
    render();
    void refresh();
  }).catch(() => { /* polling is the recovery path */ });
  render();
  void refresh();
  window.setInterval(() => void refresh(), 2000);
}
