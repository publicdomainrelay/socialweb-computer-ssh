import { createOAuthAgentFromSession, decodeJwtExp } from "@publicdomainrelay/atproto-helpers";
import type { AccountSessions, SessionStore } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

export interface AccountSessionsOptions {
  sessionStore: SessionStore;
  /** Refresh when less than this remains. Access tokens live 15 minutes. */
  refreshMarginMs?: number;
  /** The client_id the stored session was issued to; a refresh must use it. */
  clientId?: string;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

const DEFAULT_MARGIN_MS = 120_000;

/**
 * A running child that outlives its access token leaves this next to its lease.
 * A file, not a socket: both processes are on one host, the directory is already
 * 0700 and the lease 0600, and it needs no listener, no port and no secret.
 */
const REFRESH_REQUEST_SUFFIX = ".refresh-request";
const SWEEP_INTERVAL_MS = 1_000;

/**
 * The single owner of each account's OAuth session.
 *
 * Every SSH connection used to take the session under a per-account lock held
 * for the whole provisioning run, so a second connection for the same account
 * waited minutes in silence. Two things made that necessary and neither does
 * any more: the lock now covers only a refresh, and everything downstream gets
 * a copy it never rotates.
 *
 * Refresh tokens are single-use, and on a production authorization server
 * replaying one deletes the whole session rather than failing, so "only one
 * refresher per account" is a correctness requirement, not an optimization.
 */
export function createAccountSessions(opts: AccountSessionsOptions): AccountSessions {
  const marginMs = opts.refreshMarginMs ?? DEFAULT_MARGIN_MS;
  const log = opts.log ?? (() => {});
  const leases = new Map<string, { did: string; path: string }>();
  let sweeping: Promise<void> | null = null;

  async function writeLease(path: string, session: OAuthSessionData): Promise<void> {
    await Deno.writeTextFile(path, JSON.stringify({ ...session, refreshJwt: "" }, null, 2), { mode: 0o600 });
  }

  /**
   * Serve any child that asked for a token. One refresh per account, then every
   * live lease for it is rewritten -- a refresh invalidates the siblings' access
   * tokens on a production authorization server, so they all need the new one.
   */
  async function sweep(): Promise<void> {
    for (const [did, entries] of groupByDid()) {
      const asked = entries.some((e) => existsSync(`${e.path}${REFRESH_REQUEST_SUFFIX}`));
      if (!asked) continue;
      for (const e of entries) await Deno.remove(`${e.path}${REFRESH_REQUEST_SUFFIX}`).catch(() => {});
      try {
        const session = await opts.sessionStore.withAccount(did, () => refreshNow(did));
        for (const e of entries) await writeLease(e.path, session);
        log("lease_refreshed_on_request", { did, leases: entries.length });
      } catch (err) {
        // Leave the request files absent: the child times out and fails its run
        // rather than waiting forever for a token that is not coming.
        log("lease_refresh_failed", { did, error: String(err) });
      }
    }
  }

  function groupByDid(): Map<string, Array<{ did: string; path: string }>> {
    const grouped = new Map<string, Array<{ did: string; path: string }>>();
    for (const entry of leases.values()) {
      const list = grouped.get(entry.did) ?? [];
      list.push(entry);
      grouped.set(entry.did, list);
    }
    return grouped;
  }

  function existsSync(path: string): boolean {
    try {
      Deno.statSync(path);
      return true;
    } catch {
      return false;
    }
  }

  /** Refresh unconditionally, and persist: the caller holds the account lock. */
  async function refreshNow(did: string): Promise<OAuthSessionData> {
    const stored = await opts.sessionStore.get(did);
    if (!stored) throw new Error(`no oauth session stored for ${did}`);
    let updated = stored;
    const agent = await createOAuthAgentFromSession(stored, {
      clientId: opts.clientId,
      saveSession: async (session) => {
        updated = session;
      },
    });
    try {
      await agent.proactiveRefresh();
    } finally {
      (agent as unknown as { dispose?: () => void }).dispose?.();
    }
    await opts.sessionStore.set(did, updated);
    log("session_refreshed", { did, expiresAt: decodeJwtExp(updated.accessJwt) });
    return updated;
  }

  const timer = setInterval(() => {
    if (sweeping) return;
    sweeping = sweep().catch(() => {}).finally(() => {
      sweeping = null;
    });
  }, SWEEP_INTERVAL_MS);
  Deno.unrefTimer?.(timer);

  /**
   * Held only around the check-and-maybe-refresh, never around a run. Serialized
   * per account so a second caller cannot pass the freshness check against a
   * token the first is about to rotate.
   */
  async function freshSession(did: string): Promise<OAuthSessionData> {
    const stored = await opts.sessionStore.get(did);
    if (!stored) throw new Error(`no oauth session stored for ${did}`);

    const exp = decodeJwtExp(stored.accessJwt);
    if (exp !== null && exp - Date.now() > marginMs) return stored;
    return await refreshNow(did);
  }

  return {
    async lease(did, leasePath) {
      const session = await opts.sessionStore.withAccount(did, () => freshSession(did));
      await writeLease(leasePath, session);
      leases.set(leasePath, { did, path: leasePath });
    },

    release(leasePath) {
      leases.delete(leasePath);
    },

    async shutdown() {
      clearInterval(timer);
    },
  };
}
