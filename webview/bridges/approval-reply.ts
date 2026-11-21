/** One in-flight trusted desktop approval reply; only backend true is success. */
export type ApprovalReplyResult = 'accepted' | 'expired' | 'busy';

export class ApprovalReplyCoordinator {
  private active = false;

  get inFlight(): boolean {
    return this.active;
  }

  async tryRespond(
    id: string,
    allow: boolean,
    respond: (id: string, allow: boolean) => Promise<boolean>,
  ): Promise<ApprovalReplyResult> {
    if (this.active) return 'busy';
    this.active = true;
    try {
      // The Rust gate returns false if a UUID timed out, was cancelled, or
      // has already been resolved. Never turn false/undefined into success.
      const acknowledged = await respond(id, allow);
      return acknowledged === true ? 'accepted' : 'expired';
    } finally {
      // An IPC error must not permanently disable both approval buttons.
      this.active = false;
    }
  }
}
