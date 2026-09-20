import { createFactory } from "@hono/hono/factory";
import type { Context } from "@hono/hono";
import type { CocorePairing, SessionVerifier, VerifiedSession } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

export interface CocorePairFactoryOptions {
  pairing: CocorePairing;
  verifier: SessionVerifier;
  maxBodyBytes?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

const DEFAULT_MAX_BODY = 16 * 1024;

/**
 * The cocore pairing endpoints the page drives.
 *
 * Every one of them takes the deposited OAuth session as its body, for the same
 * reason POST /session does: the blob is the credential, and the pairing is for
 * a DID that has proved itself against its own PDS. Identity is established
 * once per call rather than carried in a cookie, because this server has no
 * session of its own to carry it in.
 */
export function createCocorePairFactory(opts: CocorePairFactoryOptions) {
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const log = opts.log ?? (() => {});

  type Verified = { ok: true; verified: VerifiedSession } | { ok: false; response: Response };

  async function verifiedSession(c: Context): Promise<Verified> {
    const declared = Number(c.req.header("content-length") ?? "0");
    if (Number.isFinite(declared) && declared > maxBodyBytes) {
      return { ok: false, response: c.json({ error: "body too large" }, 413) };
    }
    const text = await c.req.text();
    if (text.length > maxBodyBytes) {
      return { ok: false, response: c.json({ error: "body too large" }, 413) };
    }

    let parsed: OAuthSessionData;
    try {
      parsed = JSON.parse(text) as OAuthSessionData;
    } catch {
      return { ok: false, response: c.json({ error: "expected a JSON session" }, 400) };
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      return { ok: false, response: c.json({ error: "expected a JSON session" }, 400) };
    }

    const verified = await opts.verifier.verify(parsed);
    if (!verified) {
      log("cocore_session_rejected", { did: parsed.userDid });
      return { ok: false, response: c.json({ error: "session did not verify against its PDS" }, 401) };
    }
    return { ok: true, verified };
  }

  return createFactory({
    initApp: (app) => {
      // Whether this account already has a token, so a returning sign-in is not
      // walked through a pairing it has already done.
      app.post("/cocore/status", async (c) => {
        const check = await verifiedSession(c);
        if (!check.ok) return check.response;
        const token = await opts.pairing.token(check.verified.did);
        return c.json({
          paired: token !== undefined,
          accountDid: token?.accountDid ?? null,
          pairedAt: token?.pairedAt ?? null,
        });
      });

      // Begin a pairing. The deviceId co/core hands back is the secret that
      // later reads the key, so it stays in the pairing and never reaches the
      // browser; the browser gets an opaque pairId to poll with instead.
      app.post("/cocore/pair/start", async (c) => {
        const check = await verifiedSession(c);
        if (!check.ok) return check.response;
        try {
          const started = await opts.pairing.start(check.verified.did);
          return c.json(started);
        } catch (err) {
          log("cocore_pairing_start_failed", { did: check.verified.did, error: String(err) });
          return c.json({ error: String(err instanceof Error ? err.message : err) }, 502);
        }
      });

      app.post("/cocore/pair/poll", async (c) => {
        const body = await c.req.json().catch(() => null) as { pairId?: unknown } | null;
        const pairId = typeof body?.pairId === "string" ? body.pairId : "";
        if (!pairId) return c.json({ error: "expected a pairId" }, 400);
        return c.json({ status: await opts.pairing.poll(pairId) });
      });
    },
  });
}
