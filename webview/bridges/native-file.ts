/**
 * Staged native file client. No direct IPC content fallback, retries,
 * credential forwarding, ticket URL, or diagnostic logging.
 * Not wired into the public bridge until native integration is verified.
 */
const REDEEM = 'security-agent-file://localhost/redeem';
const DENIED = 'File read authorization changed';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface NativeFileResult {
  path: string;
  content: string;
}

export async function redeemNativeFile(
  prepare: () => Promise<unknown>,
  fetchResponse: typeof fetch = fetch,
  signal?: AbortSignal,
): Promise<NativeFileResult> {
  try {
    if (signal?.aborted) throw new Error(DENIED);
    const ticket = await prepare();
    if (signal?.aborted || typeof ticket !== 'string' ||
        ticket.length !== 36 || !UUID.test(ticket)) {
      throw new Error(DENIED);
    }
    const response = await fetchResponse(REDEEM, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      headers: { 'Content-Type': 'text/plain' },
      body: ticket,
      signal,
    });
    if (signal?.aborted || !response.ok) throw new Error(DENIED);
    const value: unknown = await response.json();
    if (signal?.aborted || !value || typeof value !== 'object' ||
        !('path' in value) || typeof value.path !== 'string' ||
        !('content' in value) || typeof value.content !== 'string') {
      throw new Error(DENIED);
    }
    return { path: value.path, content: value.content };
  } catch {
    // No path, ticket, response body or native exception is exposed.
    // Abandoned preparations expire in the bounded native ticket store.
    throw new Error(DENIED);
  }
}
