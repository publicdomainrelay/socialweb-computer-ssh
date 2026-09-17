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

  return {
    /**
     * The lease deliberately carries no refresh token. The child is told it may
     * not refresh, but a copy that *could* would be one bad code path away from
     * a second rotation -- which on a production authorization server deletes
     * the account's session outright.
     */
    lease: async (did) => {
      const session = await opts.sessionStore.withAccount(did, () => freshSession(did));
      return { ...session, refreshJwt: "" };
    },

    async shutdown() {
      // Refresh agents are built per refresh and disposed immediately, so there
      // is nothing long-lived to release. Kept for the interface contract.
    },
  };
}
