import { assertEquals } from "@std/assert";
import { Hono } from "@hono/hono";
import { createWebFactory } from "@publicdomainrelay/hono-factory-socialweb-computer-oauth";
import { createFileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import type { SessionVerifier } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const CLAIMED = "did:plc:claimed";
const ACTUAL = "did:plc:actual";

function session(userDid: string): OAuthSessionData {
  return {
    accessJwt: "access",
    refreshJwt: "refresh",
    userDid,
    handle: "alice.test",
    pds: "https://pds.test",
    dpopPublicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    dpopPrivateJwk: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
  };
}

async function harness(verifier?: SessionVerifier) {
  const dir = await Deno.makeTempDir({ prefix: "swc-web-test-" });
  const store = createFileSessionStore(`${dir}/oauth-sessions.json`);
  const app: Hono = createWebFactory({
    sessionStore: store,
    verifier: verifier ?? {
      verify: async (s) => (s.userDid === ACTUAL ? { did: ACTUAL, handle: "alice.test" } : null),
    },
    scope: "atproto repo:com.example.thing?action=create",
  }).createApp();
  return { app, store, cleanup: () => Deno.remove(dir, { recursive: true }).catch(() => {}) };
}

function post(app: Hono, body: string) {
  return app.fetch(new Request("http://localhost/session", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  }));
}

Deno.test("web serves the client metadata document from the configured scope", async () => {
  const h = await harness();
  try {
    const res = await h.app.fetch(new Request("http://localhost/oauth-client-metadata.json"));
    assertEquals(res.status, 200);
    const body = await res.json();
    assertEquals(body.scope, "atproto repo:com.example.thing?action=create");
    assertEquals(body.client_id, "http://localhost/oauth-client-metadata.json");
    assertEquals(body.token_endpoint_auth_method, "none");
    assertEquals(body.dpop_bound_access_tokens, true);
  } finally {
    await h.cleanup();
  }
});

Deno.test("web stores a verified session under the DID the PDS confirmed", async () => {
  const h = await harness();
  try {
    // The blob claims one DID; the verifier says otherwise. The confirmed DID wins.
    const res = await post(h.app, JSON.stringify(session(ACTUAL)));
    assertEquals(res.status, 200);
    assertEquals(await res.json(), { did: ACTUAL, handle: "alice.test" });
    assertEquals((await h.store.get(ACTUAL))?.accessJwt, "access");
    assertEquals(await h.store.get(CLAIMED), undefined);
  } finally {
    await h.cleanup();
  }
});

Deno.test("web refuses a session the PDS does not confirm", async () => {
  const h = await harness();
  try {
    const res = await post(h.app, JSON.stringify(session(CLAIMED)));
    assertEquals(res.status, 401);
    assertEquals(await h.store.get(CLAIMED), undefined);
    assertEquals(await h.store.list(), []);
  } finally {
    await h.cleanup();
  }
});

Deno.test("web refuses a body that is not a JSON object", async () => {
  const h = await harness();
  try {
    assertEquals((await post(h.app, "not json")).status, 400);
    assertEquals((await post(h.app, "[1,2,3]")).status, 400);
    assertEquals((await post(h.app, "null")).status, 400);
  } finally {
    await h.cleanup();
  }
});

Deno.test("web caps the deposit body", async () => {
  const h = await harness();
  try {
    const huge = JSON.stringify({ ...session(ACTUAL), padding: "x".repeat(64 * 1024) });
    assertEquals((await post(h.app, huge)).status, 413);
    assertEquals((await post(h.app, huge)).status, 413);
  } finally {
    await h.cleanup();
  }
});
