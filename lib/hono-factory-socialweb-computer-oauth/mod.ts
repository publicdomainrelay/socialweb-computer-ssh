import { createFactory } from "@hono/hono/factory";
import type { SessionVerifier } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";
import type { SessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";

export interface WebFactoryOptions {
  sessionStore: SessionStore;
  verifier: SessionVerifier;
  scope: string;
  /**
   * Public origin this deployment is reached at, e.g. https://ssh.example.com.
   *
   * Required whenever the app sits behind a TLS terminator: the client_id must
   * be an https URL with no port, and a proxied request arrives as plain http,
   * so the request origin would publish an http:// client_id that authorization
   * servers refuse. Set explicitly rather than read from X-Forwarded-* -- the
   * header is only trustworthy when the listener is unreachable except through
   * the proxy, which is a property of the deployment, not of this code.
   */
  publicOrigin?: string;
  /**
   * Hostname the page should tell people to ssh to.
   *
   * More than one name can reach this door -- an apex domain resolving to the
   * same address, for instance -- and the page would otherwise offer whichever
   * one it happens to be served from. Defaults to the public origin's hostname.
   */
  sshPublicHost?: string;
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
  const publicOrigin = opts.publicOrigin?.replace(/\/+$/, "");

  return createFactory({
    initApp: (app) => {
      // What the page should put in its connect example. Served rather than
      // derived client-side because only the server knows which names reach it.
      app.get("/connect.json", (c) => {
        const origin = publicOrigin ?? new URL(c.req.url).origin;
        return c.json({
          sshHost: opts.sshPublicHost ?? new URL(origin).hostname,
        });
      });

      // The browser runs the whole OAuth flow itself, client-side; this document
      // is what its client_id points at when the app is not on loopback.
      app.get(clientMetadataPath, (c) => {
        const origin = publicOrigin ?? new URL(c.req.url).origin;
        return c.json({
          client_id: `${origin}${clientMetadataPath}`,
          application_type: "web",
          dpop_bound_access_tokens: true,
          grant_types: ["authorization_code", "refresh_token"],
          response_types: ["code"],
          // Both spellings, because the page strips trailing slashes from its
          // redirect_uri and the authorization server requires an exact match
          // against a declared URI.
          redirect_uris: [`${origin}/`, origin],
          scope: opts.scope,
          token_endpoint_auth_method: "none",
          client_name: opts.clientName ?? "socialweb-computer-ssh",
        });
      });

      // The browser deposits the session it obtained so the SSH half can use it
      // to act as the signed-in account. It is unauthenticated by nature --
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
