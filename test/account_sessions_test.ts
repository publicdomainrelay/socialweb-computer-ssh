import { assertEquals, assertRejects } from "@std/assert";
import { Hono } from "@hono/hono";
import { createFileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { createAccountSessions } from "@publicdomainrelay/socialweb-computer-account-sessions-atproto";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const DID = "did:plc:sessions";
const OTHER = "did:plc:other";

function b64url(value: unknown): string {
  return btoa(JSON.stringify(value)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** A JWT whose payload decodes, so exp can be read without verifying. */
function jwtExpiringIn(seconds: number): string {
  return `${b64url({ alg: "ES256" })}.${b64url({ exp: Math.floor(Date.now() / 1000) + seconds })}.sig`;
}

// A refresh imports the DPoP key, so the fixture has to be a real one.
const dpop = await (async () => {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
  return {
    dpopPublicJwk: await crypto.subtle.exportKey("jwk", pair.publicKey) as Record<string, string>,
    dpopPrivateJwk: await crypto.subtle.exportKey("jwk", pair.privateKey) as Record<string, string>,
  };
})();

function session(accessJwt: string, userDid = DID): OAuthSessionData {
  return {
    accessJwt,
    refreshJwt: "refresh",
    userDid,
    handle: "alice.test",
    pds: "https://pds.test",
    ...dpop,
  };
}

/**
 * The reference authorization server's semantics, which are the ones that
 * matter: a refresh rotates the token, and hono-pds's permissive behaviour
 * would let a broken design pass.
 */
async function tokenEndpoint() {
  const state = { refreshes: 0 };
  const app = new Hono();
  app.get("/.well-known/oauth-protected-resource", (c) =>
    c.json({ authorization_servers: [origin.value] }));
  app.get("/.well-known/oauth-authorization-server", (c) =>
    c.json({ issuer: origin.value, token_endpoint: `${origin.value}/token`, authorization_endpoint: `${origin.value}/authorize` }));
  app.post("/token", async (c) => {
    const form = new URLSearchParams(await c.req.text());
    if (form.get("grant_type") !== "refresh_token") return c.json({ error: "unsupported_grant_type" }, 400);
    state.refreshes += 1;
    return c.json({
      access_token: jwtExpiringIn(900),
      refresh_token: `refresh-${state.refreshes}`,
      token_type: "DPoP",
      expires_in: 900,
    });
  });
  const origin = { value: "" };
  const { promise, resolve } = Promise.withResolvers<number>();
  const server = Deno.serve({ port: 0, hostname: "127.0.0.1", onListen: (a) => resolve((a as Deno.NetAddr).port) }, app.fetch);
  const port = await promise;
  origin.value = `http://127.0.0.1:${port}`;
  return { pds: origin.value, state, close: () => server.shutdown() };
}

async function harness(expiresInSec: number, pds: string) {
  const dir = await Deno.makeTempDir({ prefix: "swc-sessions-test-" });
  const path = `${dir}/oauth-sessions.json`;
  const store = createFileSessionStore(path);
  await store.set(DID, { ...session(jwtExpiringIn(expiresInSec)), pds });
  await store.set(OTHER, { ...session(jwtExpiringIn(expiresInSec), OTHER), userDid: OTHER, pds });
  return { path, store, dir, cleanup: () => Deno.remove(dir, { recursive: true }).catch(() => {}) };
}

/** Lease into a temp file the way the runner does, and read it back. */
async function leaseInto(
  sessions: ReturnType<typeof createAccountSessions>,
  did: string,
  n = 0,
): Promise<OAuthSessionData> {
  const dir = await Deno.makeTempDir({ prefix: "swc-lease-read-" });
  const path = `${dir}/session-${n}.json`;
  await sessions.lease(did, path);
  return JSON.parse(await Deno.readTextFile(path)) as OAuthSessionData;
}

Deno.test("a lease of a still-valid token is handed out without touching the network", async () => {
  const as = await tokenEndpoint();
  const h = await harness(900, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    const leased = await leaseInto(sessions, DID);
    assertEquals(leased.userDid, DID);
    assertEquals(leased.accessJwt.includes("."), true);
    assertEquals(as.state.refreshes, 0, "a valid token must not be refreshed");
  } finally {
    await h.cleanup();
    await as.close();
  }
});

Deno.test("an about-to-expire token is refreshed exactly once for concurrent leases", async () => {
  const as = await tokenEndpoint();
  const h = await harness(30, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    const leased = await Promise.all([0, 1, 2, 3].map((i) => leaseInto(sessions, DID, i)));
    assertEquals(as.state.refreshes, 1, "concurrent leases must coalesce into one refresh");
    assertEquals(new Set(leased.map((s) => s.accessJwt)).size, 1);
    // The refreshed session is what the store now holds.
    assertEquals((await h.store.get(DID))?.refreshJwt, "refresh-1");
  } finally {
    await h.cleanup();
    await as.close();
  }
});

Deno.test("leases for one account do not serialize against each other", async () => {
  const as = await tokenEndpoint();
  const h = await harness(900, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    const started = Date.now();
    const [a, b] = await Promise.all([leaseInto(sessions, DID, 0), leaseInto(sessions, DID, 1)]);
    assertEquals(a.userDid, DID);
    assertEquals(b.userDid, DID);
    // The old design held a per-account lock for the whole provisioning run;
    // this must be near-instant, not a queue.
    assertEquals(Date.now() - started < 2_000, true);
  } finally {
    await h.cleanup();
    await as.close();
  }
});

Deno.test("leases for different accounts do not clobber each other", async () => {
  const as = await tokenEndpoint();
  const h = await harness(900, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    const [a, b] = await Promise.all([leaseInto(sessions, DID, 0), leaseInto(sessions, OTHER, 1)]);
    assertEquals(a.userDid, DID);
    assertEquals(b.userDid, OTHER);
  } finally {
    await h.cleanup();
    await as.close();
  }
});

Deno.test("leasing an account with no stored session is an error", async () => {
  const as = await tokenEndpoint();
  const h = await harness(900, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    await assertRejects(() => leaseInto(sessions, "did:plc:nobody"), Error, "no oauth session stored");
  } finally {
    await h.cleanup();
    await as.close();
  }
});

Deno.test("a corrupt store is quarantined, not silently emptied", async () => {
  const dir = await Deno.makeTempDir({ prefix: "swc-sessions-test-" });
  const path = `${dir}/oauth-sessions.json`;
  try {
    await Deno.writeTextFile(path, "{ this is not json");
    const corruptSeen: string[] = [];
    const store = createFileSessionStore(path, { onCorrupt: ({ quarantine }) => corruptSeen.push(quarantine) });
    assertEquals(await store.list(), []);
    assertEquals(corruptSeen.length, 1);
    assertEquals(await Deno.readTextFile(corruptSeen[0]), "{ this is not json");
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("the session store is written owner-only", async () => {
  const dir = await Deno.makeTempDir({ prefix: "swc-sessions-test-" });
  const path = `${dir}/oauth-sessions.json`;
  try {
    const store = createFileSessionStore(path);
    await store.set(DID, session(jwtExpiringIn(900)));
    assertEquals(((await Deno.stat(path)).mode ?? 0) & 0o777, 0o600);
  } finally {
    await Deno.remove(dir, { recursive: true }).catch(() => {});
  }
});

Deno.test("a lease carries no refresh token", async () => {
  const as = await tokenEndpoint();
  const h = await harness(900, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    const leased = await leaseInto(sessions, DID);
    // The child is told it may not refresh; a lease that *could* would be one
    // bad code path from a second rotation, which destroys the session.
    assertEquals(leased.refreshJwt, "");
    // The owner keeps the real one.
    assertEquals((await h.store.get(DID))?.refreshJwt, "refresh");
  } finally {
    await h.cleanup();
    await as.close();
  }
});

Deno.test("a lease that asks for a token gets one, and its siblings get it too", async () => {
  const as = await tokenEndpoint();
  const h = await harness(900, as.pds);
  try {
    const sessions = createAccountSessions({ sessionStore: h.store });
    const dir = await Deno.makeTempDir({ prefix: "swc-lease-run-" });
    const first = `${dir}/a.json`;
    const second = `${dir}/b.json`;
    await sessions.lease(DID, first);
    await sessions.lease(DID, second);
    const before = JSON.parse(await Deno.readTextFile(first)).accessJwt;
    assertEquals(as.state.refreshes, 0);

    // What a child does when its token is rejected mid-run.
    await Deno.writeTextFile(`${first}.refresh-request`, String(Date.now()));

    const deadline = Date.now() + 15_000;
    let after = before;
    while (Date.now() < deadline && after === before) {
      await new Promise((r) => setTimeout(r, 250));
      after = JSON.parse(await Deno.readTextFile(first)).accessJwt;
    }

    assertEquals(as.state.refreshes, 1, "the owner must refresh once, not per lease");
    assertEquals(after !== before, true, "the asking lease must be rewritten");
    // A refresh kills the siblings' tokens on a production server, so they are
    // rewritten too rather than left holding a dead one.
    assertEquals(JSON.parse(await Deno.readTextFile(second)).accessJwt, after);
    // And the lease still carries no refresh token.
    assertEquals(JSON.parse(await Deno.readTextFile(first)).refreshJwt, "");
    assertEquals((await h.store.get(DID))?.refreshJwt, "refresh-1");

    sessions.release(first);
    sessions.release(second);
  } finally {
    await h.cleanup();
    await as.close();
  }
});
