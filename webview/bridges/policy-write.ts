/** Serialize shell permission writes from the trusted desktop settings UI. */
export type ShellPolicy = 'auto' | 'ask' | 'disable';

export class PolicyWriteCoordinator {
  private active = false;

  get inFlight(): boolean {
    return this.active;
  }

  // A rejected or cancelled write releases the gate, but never reports
  // success. The caller owns displaying only the last acknowledged value.
  async tryWrite(
    policy: ShellPolicy,
    persist: (policy: ShellPolicy) => Promise<void>,
  ): Promise<boolean> {
    if (this.active) return false;
    this.active = true;
    try {
      await persist(policy);
      return true;
    } finally {
      this.active = false;
    }
  }
}
