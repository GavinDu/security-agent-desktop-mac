import type { ApprovalEvent } from './connectors';

const MAX_PENDING = 32;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const same = (a: ApprovalEvent, b: ApprovalEvent): boolean =>
  a.id === b.id && a.tool === b.tool && a.preview === b.preview;

function parseSnapshot(value: unknown): ApprovalEvent[] | null {
  if (!Array.isArray(value) || value.length > MAX_PENDING) return null;
  const ids = new Set<string>();
  const items: ApprovalEvent[] = [];
  for (const item of value) {
    if (!item || typeof item !== 'object' ||
        typeof item.id !== 'string' || !UUID.test(item.id) || ids.has(item.id) ||
        typeof item.tool !== 'string' || !/^[A-Za-z0-9_-]{1,64}$/.test(item.tool) ||
        typeof item.preview !== 'string' || !/^[ -~]{1,8192}$/.test(item.preview)) return null;
    ids.add(item.id);
    items.push({ id: item.id, tool: item.tool, preview: item.preview });
  }
  return items;
}

/** Backend snapshot is only a point-in-time readback, never a grant.
 * Selection is explicit, immutable by identity+preview, and never advances. */
export class ApprovalInbox {
  private items: ApprovalEvent[] = [];
  private selected: ApprovalEvent | null = null;
  private version = 0;
  private known = false;
  private responding = false;

  get available(): boolean { return this.known; }
  get busy(): boolean { return this.responding; }
  get entries(): ApprovalEvent[] { return this.items.map(item => ({ ...item })); }
  get current(): ApprovalEvent | null {
    return this.known && !this.responding && this.selected ? { ...this.selected } : null;
  }
  get selection(): string { return this.selected?.id ?? ''; }

  beginRead(): number { return this.version; }

  invalidate(): void {
    this.version += 1;
    this.known = false;
  }

  failRead(version: number): void {
    if (version !== this.version) return;
    this.invalidate();
    this.items = [];
    this.selected = null;
  }

  applyRead(version: number, value: unknown): boolean {
    if (version !== this.version || this.responding) return false;
    const items = parseSnapshot(value);
    if (!items) {
      this.failRead(version);
      return false;
    }
    if (this.selected && !items.some(item => same(item, this.selected!))) {
      this.selected = null;
    }
    this.items = items;
    this.known = true;
    return true;
  }

  select(id: string): void {
    if (!this.known || this.responding) return;
    this.selected = this.items.find(item => item.id === id) ?? null;
  }

  beginResponse(): ApprovalEvent | null {
    const current = this.current;
    if (!current) return null;
    this.responding = true;
    this.selected = null;
    this.invalidate();
    return current;
  }

  finishResponse(): void {
    this.responding = false;
    this.selected = null;
    this.items = [];
    this.invalidate();
  }
}
