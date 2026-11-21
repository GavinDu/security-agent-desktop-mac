/** Only a current, fully acknowledged backend root snapshot may feed new grants. */
export class RootSnapshotCoordinator {
  private generation = 0;
  private mutationPending = false;
  private confirmed = false;
  private roots: string[] = [];

  get canWrite(): boolean {
    return this.confirmed && !this.mutationPending;
  }

  // Clearing all roots is safe without a verified snapshot; it cannot add
  // back any old path. Still serialize it behind an in-flight mutation.
  get canRevoke(): boolean {
    return !this.mutationPending;
  }

  snapshot(): string[] {
    // Return a defensive copy; callers cannot mutate acknowledged roots.
    return this.canWrite ? [...this.roots] : [];
  }

  beginRefresh(): number {
    // Latest refresh wins, including concurrent readbacks.
    return ++this.generation;
  }

  applyRefresh(epoch: number, roots: readonly string[]): boolean {
    if (this.mutationPending || epoch !== this.generation) return false;
    this.roots = [...roots];
    this.confirmed = true;
    return true;
  }

  failRefresh(epoch: number): boolean {
    if (this.mutationPending || epoch !== this.generation) return false;
    this.confirmed = false;
    this.generation++;
    return true;
  }

  startMutation(revokingAll = false): boolean {
    if (!this.canRevoke || (!revokingAll && !this.canWrite)) return false;
    this.mutationPending = true;
    this.confirmed = false;
    this.generation++; // revoke all outstanding refresh tokens
    return true;
  }

  finishMutation(): void {
    if (!this.mutationPending) throw new Error('Root mutation was not active');
    this.mutationPending = false;
    this.confirmed = false;
    this.generation++; // reject any refresh begun while mutating
  }
}
