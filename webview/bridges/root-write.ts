/** One trusted-window root grant/revocation IPC mutation at a time. */
export class RootWriteCoordinator {
  private active = false;

  get inFlight(): boolean {
    return this.active;
  }

  // Freeze the requested grant set before the first await. Another click
  // cannot submit an overtaking mutation or modify these exact arguments.
  async tryWrite(
    requestedRoots: readonly string[],
    persist: (roots: string[]) => Promise<void>,
  ): Promise<boolean> {
    if (this.active) return false;
    this.active = true;
    try {
      const roots = [...requestedRoots];
      await persist(roots);
      return true;
    } finally {
      this.active = false;
    }
  }
}
