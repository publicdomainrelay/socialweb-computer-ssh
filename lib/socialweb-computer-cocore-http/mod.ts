import type { JsonFileStore } from "@publicdomainrelay/json-file-store-fs";
import type { SecretEntry } from "@publicdomainrelay/secrets-common";
import type {
  CocorePairing,
  CocorePairingStarted,
  CocorePairingStatus,
  CocoreToken,
} from "@publicdomainrelay/socialweb-computer-abc";

export const DEVICE_PAIR_START_NSID = "dev.cocore.devicePair.start";
export const DEVICE_PAIR_POLL_NSID = "dev.cocore.devicePair.poll";

/**
 * Where the guest's pi agent loads its provider credentials from.
 *
 * Taken from the --secrets example in the org README, which is the only place
 * this path is already written down; a second convention for the same file
 * would be worse than none.
 */
export const COCORE_CONFIG_PATH_VM = "/root/.pi/agent/cocore-config.json";

/**
 * The guest's cocore credential, as a SecretEntry.
 *
 * The value is JSON rather than the bare token because the capability writes it
 * verbatim into the file the agent reads. `--secrets` auto-stringifies objects,
 * but building the string here keeps the shape in one place.
 */
export function cocoreSecretEntry(token: string): SecretEntry {
  return { path: COCORE_CONFIG_PATH_VM, value: JSON.stringify({ apiKey: token }) };
}

export interface CocorePairingOptions {
  /**
   * Base URL the pairing endpoints hang off, e.g. https://cocore.dev/api.
   *
   * Both cocore.dev/api and appview.cocore.dev serve the same backend; this is
   * a base rather than a host so a test can point the whole flow at a local
   * app, which is the only way to exercise an approved pairing without a human
   * at the verification URI.
   */
  apiBaseUrl: string;
  /** Where approved tokens are filed, keyed by atmosphere DID. */
  tokens: JsonFileStore<CocoreToken>;
  appName: string;
  appDid: string;
  keyName: string;
  returnUrl: string;
  ttlMs?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
  fetch?: typeof globalThis.fetch;
}

const DEFAULT_TTL_MS = 10 * 60_000;

/**
 * The key out of an approved poll.
 *
 * co/core documents the field as `session.apiKey`, and nothing else has been
 * observed because completing a pairing needs a human at the verification URI.
 * This repo has already been bitten by exactly this class of drift -- cocore-api
 * types `.token` where the README reads `.secret` -- so the three plausible
 * names are accepted here and nowhere else. One function knows the field name,
 * which makes a rename a one-line fix rather than a hunt.
 */
export function sessionKey(session: Record<string, unknown>): string | undefined {
  for (const name of ["apiKey", "token", "secret", "key"]) {
    const value = session[name];
    if (typeof value === "string" && value) return value;
  }
  return undefined;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function createCocorePairing(opts: CocorePairingOptions): CocorePairing {
  const base = opts.apiBaseUrl.replace(/\/+$/, "");
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
  const log = opts.log ?? (() => {});
  const fetchImpl = opts.fetch ?? globalThis.fetch;

  /**
   * pairId -> the pairing it names.
   *
   * Keyed by a fresh random id rather than the account DID so that a poll,
   * which is reachable without a session, cannot advance or probe another
   * account's pairing. The deviceId inside is the secret that reads the key and
   * never leaves this process.
   *
   * In memory only: a restart mid-pairing means the user clicks again, which is
   * cheaper than persisting a secret for a flow that lasts ten minutes.
   * ponytail: in-memory, persist beside the token store if restarts ever land
   * mid-pairing often enough to matter.
   */
  const pending = new Map<string, { did: string; deviceId: string; expiresAt: number }>();

  function sweep(): void {
    const now = Date.now();
    for (const [id, entry] of pending) {
      if (entry.expiresAt <= now) pending.delete(id);
    }
  }

  return {
    async start(did: string): Promise<CocorePairingStarted> {
      sweep();

      const res = await fetchImpl(`${base}/xrpc/${DEVICE_PAIR_START_NSID}`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          appName: opts.appName,
          appDid: opts.appDid,
          keyName: opts.keyName,
          returnUrl: opts.returnUrl,
        }),
      });
      const body = asRecord(await res.json().catch(() => null));
      if (!res.ok || !body) {
        const detail = body?.message ?? body?.error ?? `HTTP ${res.status}`;
        throw new Error(`cocore pairing could not start: ${detail}`);
      }

      const deviceId = typeof body.deviceId === "string" ? body.deviceId : "";
      const userCode = typeof body.userCode === "string" ? body.userCode : "";
      const verificationUri = typeof body.verificationUri === "string" ? body.verificationUri : "";
      if (!deviceId || !verificationUri) {
        throw new Error("cocore pairing response carried no deviceId or verificationUri");
      }

      const expiresInSecs = typeof body.expiresInSecs === "number" ? body.expiresInSecs : undefined;
      const intervalSecs = typeof body.pollIntervalSecs === "number" ? body.pollIntervalSecs : 5;

      const pairId = crypto.randomUUID();
      pending.set(pairId, {
        did,
        deviceId,
        expiresAt: Date.now() + (expiresInSecs ? expiresInSecs * 1000 : ttlMs),
      });
      log("cocore_pairing_started", { did, hasUserCode: userCode.length > 0 });

      return { pairId, userCode, verificationUri, intervalSecs };
    },

    async poll(pairId: string): Promise<CocorePairingStatus> {
      const entry = pending.get(pairId);
      if (!entry) return "expired";
      if (entry.expiresAt <= Date.now()) {
        pending.delete(pairId);
        return "expired";
      }

      const res = await fetchImpl(
        `${base}/xrpc/${DEVICE_PAIR_POLL_NSID}?deviceId=${encodeURIComponent(entry.deviceId)}`,
      );
      const body = asRecord(await res.json().catch(() => null));
      if (!res.ok || !body) {
        // A consumed or expired pairing is gone at the far end; anything else is
        // a transport problem the caller may retry, so it stays pending rather
        // than being reported as a decision the user did not make.
        if (res.status === 404 || res.status === 410) {
          pending.delete(pairId);
          return "expired";
        }
        log("cocore_pairing_poll_failed", { status: res.status });
        return "pending";
      }

      const status = typeof body.status === "string" ? body.status : undefined;
      if (status === "denied") {
        pending.delete(pairId);
        log("cocore_pairing_denied", { did: entry.did });
        return "denied";
      }
      if (status === "expired") {
        pending.delete(pairId);
        return "expired";
      }

      const session = asRecord(body.session);
      if (!session) return "pending";

      const token = sessionKey(session);
      if (!token) {
        log("cocore_pairing_no_key_in_session", { keys: Object.keys(session).join(",") });
        return "pending";
      }

      await opts.tokens.set(entry.did, {
        token,
        ...(typeof session.apiBase === "string" ? { apiBase: session.apiBase } : {}),
        ...(typeof session.did === "string" ? { accountDid: session.did } : {}),
        pairedAt: new Date().toISOString(),
      });
      pending.delete(pairId);
      log("cocore_paired", { did: entry.did });
      return "complete";
    },

    token: (did: string) => opts.tokens.get(did),
  };
}
