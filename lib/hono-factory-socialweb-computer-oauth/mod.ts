import { createFactory } from "@hono/hono/factory";
import type { SessionStore, SessionVerifier } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

export interface WebFactoryOptions {
  sessionStore: SessionStore;
  verifier: SessionVerifier;
  scope: string;
  clientName?: string;
  clientMetadataPath?: string;
  maxBodyBytes?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

const DEFAULT_MAX_BODY = 16 * 1024;

export function createWebFactory(opts: WebFactoryOptions) {
  const clientMetadataPath = opts.clientMetadataPath ?? "/oauth-client-metadata.json";
  const maxBodyBytes = opts.maxBodyBytes ?? DEFAULT_MAX_BODY;
  const log = opts.log ?? (() => {});

  return createFactory({
    initApp: (app) => {
      // The browser runs the whole OAuth flow itself, client-side; this document
      // is what its client_id points at when the app is not on loopback.
      app.get(clientMetadataPath, (c) => c.json({
        client_id: `${new URL(c.req.url).origin}${clientMetadataPath}`,
        application_type: "web",
        dpop_bound_access_tokens: true,
        grant_types: ["authorization_code", "refresh_token"],
        response_types: ["code"],
        redirect_uris: [new URL(c.req.url).origin + "/"],
        scope: opts.scope,
        token_endpoint_auth_method: "none",
        client_name: opts.clientName ?? "socialweb-computer-ssh",
      }));

      // The browser deposits the session it obtained so the SSH half can lease
      // it into a temp dir for the requester. It is unauthenticated by nature --
      // a session blob is the credential -- so it is proved against the PDS
      // before being stored, which also means a deposit costs a real round trip
      // rather than being a cheap way to fill the store.
      app.post("/session", async (c) => {
        const declared = Number(c.req.header("content-length") ?? "0");
        if (Number.isFinite(declared) && declared > maxBodyBytes) {
          return c.json({ error: "body too large" }, 413);
        }
        const text = await c.req.text();
        if (text.length > maxBodyBytes) return c.json({ error: "body too large" }, 413);

        let parsed: OAuthSessionData;
        try {
          parsed = JSON.parse(text) as OAuthSessionData;
        } catch {
          return c.json({ error: "expected a JSON session" }, 400);
        }
        if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
          return c.json({ error: "expected a JSON session" }, 400);
        }

        const verified = await opts.verifier.verify(parsed);
        if (!verified) {
          log("session_rejected", { did: parsed.userDid });
          return c.json({ error: "session did not verify against its PDS" }, 401);
        }

        await opts.sessionStore.withAccount(verified.did, () => opts.sessionStore.set(verified.did, parsed));
        log("session_deposited", { did: verified.did, handle: verified.handle });
        return c.json({ did: verified.did, handle: verified.handle });
      });
    },
  });
}
