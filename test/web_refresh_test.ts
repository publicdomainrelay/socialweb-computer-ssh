import { assertEquals } from "@std/assert";

// The page's modules are browser JS with no JSDoc, so Deno infers signatures
// narrower than what they accept. Typed loosely here rather than annotating the
// page for the test's sake.
type PdsModule = {
  createPdsClient: (session: Record<string, unknown>) => {
    call: (nsid: string, opts?: Record<string, unknown>) => Promise<unknown>;
  };
};

async function loadPds(): Promise<PdsModule> {
  return await import("../web/lib/pds.js") as unknown as PdsModule;
}

// A returning account's access token has usually expired, and the server half
// proves a deposit with a live call of its own -- so a client that cannot renew
// its token is a client that stops working after a couple of hours. These drive
// the real client against a fake PDS rather than asserting on the source.

/** localStorage, which the page uses and Deno does not provide. */
function stubStorage() {
  const map = new Map<string, string>();
  const store = {
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => void map.set(k, String(v)),
    removeItem: (k: string) => void map.delete(k),
    clear: () => map.clear(),
    key: (i: number) => [...map.keys()][i] ?? null,
    get length() {
      return map.size;
    },
  };
  // Deno ships localStorage as an accessor whose setter ignores assignment, so
  // `globalThis.localStorage = ...` reports success and changes nothing. This is
  // also why the page's own writes would look like they vanished.
  Object.defineProperty(globalThis, "localStorage", { value: store, configurable: true, writable: true });
  return map;
}

async function sessionKeys() {
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  return {
    dpopPrivateJwk: await crypto.subtle.exportKey("jwk", kp.privateKey),
    dpopPublicJwk: await crypto.subtle.exportKey("jwk", kp.publicKey),
  };
}

interface Fake {
  origin: string;
  tokenRequests: { refreshToken: string | null; clientId: string | null; hasAth: boolean }[];
  discoveryHits: () => number;
  protectedResourceHits: () => number;
  close: () => Promise<void>;
}

async function fakePds(_opts: { withDiscovery: boolean }): Promise<Fake> {
  let origin = "";
  let discoveryHits = 0;
  let protectedResourceHits = 0;
  const tokenRequests: Fake["tokenRequests"] = [];

  const server = Deno.serve(
    {
      port: 0,
      hostname: "127.0.0.1",
      onListen: ({ port }) => { origin = `http://127.0.0.1:${port}`; },
    },
    async (req) => {
      const url = new URL(req.url);

      // The account's PDS is not its authorization server. Discovery has to make
      // both hops -- the PDS advertises the authorization servers it trusts, and
      // only then does one of them publish a token endpoint. Asking the PDS for
      // its own authorization-server metadata, which is what a single-hop guess
      // does, is a 404 against a real host.
      if (url.pathname === "/.well-known/oauth-protected-resource") {
        protectedResourceHits++;
        return Response.json({ authorization_servers: [origin] });
      }
      if (url.pathname === "/.well-known/oauth-authorization-server") {
        discoveryHits++;
        return Response.json({ token_endpoint: `${origin}/oauth/token` });
      }

      if (url.pathname === "/oauth/token") {
        const form = new URLSearchParams(await req.text());
        // The proof must be signed but must not carry `ath`: RFC 9449 wants the
        // access-token hash only when a proof travels alongside an access token.
        const proof = req.headers.get("dpop") ?? "";
        const payload = proof.split(".")[1] ?? "";
        const claims = JSON.parse(
          atob(payload.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - payload.length % 4) % 4)),
        );
        tokenRequests.push({
          refreshToken: form.get("refresh_token"),
          clientId: form.get("client_id"),
          hasAth: "ath" in claims,
        });
        // Slow enough that a second caller's 401 lands while this is in flight,
        // which is what makes the single-flight assertion mean anything.
        await new Promise((r) => setTimeout(r, 60));
        return Response.json({
          access_token: `access-${tokenRequests.length}`,
          refresh_token: `refresh-${tokenRequests.length}`,
          token_type: "DPoP",
          expires_in: 3600,
        });
      }

      if (url.pathname === "/xrpc/com.atproto.repo.listRecords") {
        const auth = req.headers.get("authorization") ?? "";
        // Only the token minted by the nth refresh is accepted, so the retry
        // cannot pass by accident.
        if (auth !== `DPoP access-${tokenRequests.length}` || tokenRequests.length === 0) {
          return Response.json({ error: "invalid_token", message: '"exp" claim timestamp check failed' }, { status: 401 });
        }
        return Response.json({ records: [{ uri: "at://x/1", value: {} }] });
      }

      return new Response("not found", { status: 404 });
    },
  );

  // Deno.serve resolves onListen synchronously before returning, so origin is set.
  return {
    origin,
    tokenRequests,
    discoveryHits: () => discoveryHits,
    protectedResourceHits: () => protectedResourceHits,
    close: () => server.shutdown(),
  };
}

async function sessionFor(pds: string, extra: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  return {
    accessJwt: "expired",
    refreshJwt: "refresh-0",
    userDid: "did:plc:test",
    handle: "alice.test",
    pds,
    clientId: "https://client.test/oauth-client-metadata.json",
    ...(await sessionKeys()),
    ...extra,
  };
}

Deno.test("an expired access token is refreshed and the call retried", async () => {
  const store = stubStorage();
  const pds = await fakePds({ withDiscovery: true });
  try {
    const { createPdsClient } = await loadPds();
    const session = await sessionFor(pds.origin, { tokenEndpoint: `${pds.origin}/oauth/token` });
    const client = createPdsClient(session);

    const body = await client.call("com.atproto.repo.listRecords", { params: { repo: "did:plc:test", collection: "x" } });
    assertEquals((body as { records: unknown[] }).records.length, 1);

    assertEquals(pds.tokenRequests.length, 1);
    assertEquals(pds.tokenRequests[0].refreshToken, "refresh-0", "the stored refresh token is the one presented");
    assertEquals(pds.tokenRequests[0].clientId, "https://client.test/oauth-client-metadata.json");
    assertEquals(pds.tokenRequests[0].hasAth, false, "a token request carries no ath");

    // The rotated pair is persisted, or the next expiry strands the session.
    assertEquals(session.accessJwt, "access-1");
    assertEquals(session.refreshJwt, "refresh-1");
    const saved = JSON.parse(store.get("swc-session") as string);
    assertEquals(saved.refreshJwt, "refresh-1", "the rotation must be written back");
  } finally {
    await pds.close();
  }
});

Deno.test("concurrent calls share one refresh, because the token rotates", async () => {
  stubStorage();
  const pds = await fakePds({ withDiscovery: true });
  try {
    const { createPdsClient } = await loadPds();
    const session = await sessionFor(pds.origin, { tokenEndpoint: `${pds.origin}/oauth/token` });
    const client = createPdsClient(session);

    await Promise.all([
      client.call("com.atproto.repo.listRecords", { params: { repo: "did:plc:test", collection: "x" } }),
      client.call("com.atproto.repo.listRecords", { params: { repo: "did:plc:test", collection: "x" } }),
    ]);

    assertEquals(pds.tokenRequests.length, 1, "a second refresh would spend the rotated token twice");
    assertEquals(session.refreshJwt, "refresh-1");
  } finally {
    await pds.close();
  }
});

Deno.test("a session with no token endpoint discovers one", async () => {
  stubStorage();
  const pds = await fakePds({ withDiscovery: true });
  try {
    const { createPdsClient } = await loadPds();
    const session = await sessionFor(pds.origin);
    const client = createPdsClient(session);

    await client.call("com.atproto.repo.listRecords", { params: { repo: "did:plc:test", collection: "x" } });

    assertEquals(pds.protectedResourceHits(), 1, "discovery starts at the PDS's protected-resource document");
    assertEquals(pds.discoveryHits(), 1, "and reaches the authorization server the PDS names");
    assertEquals(session.tokenEndpoint, `${pds.origin}/oauth/token`, "discovered once, then kept on the session");
  } finally {
    await pds.close();
  }
});

Deno.test("a refresh that fails surfaces rather than looping", async () => {
  stubStorage();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const server = Deno.serve(
    {
      port: 0,
      hostname: "127.0.0.1",
      onListen: () => {},
    },
    (req) => {
      const url = new URL(req.url);
      if (url.pathname === "/oauth/token") {
        return Response.json({ error: "invalid_grant" }, { status: 400 });
      }
      return Response.json({ error: "invalid_token" }, { status: 401 });
    },
  );
  const port = (server.addr as Deno.NetAddr).port;
  try {
    const { createPdsClient } = await loadPds();
    const session = {
      accessJwt: "expired",
      refreshJwt: "dead",
      userDid: "did:plc:test",
      handle: "alice.test",
      pds: `http://127.0.0.1:${port}`,
      clientId: "https://client.test/oauth-client-metadata.json",
      tokenEndpoint: `http://127.0.0.1:${port}/oauth/token`,
      dpopPrivateJwk: await crypto.subtle.exportKey("jwk", kp.privateKey),
      dpopPublicJwk: await crypto.subtle.exportKey("jwk", kp.publicKey),
    };
    const client = createPdsClient(session);

    let threw = "";
    try {
      await client.call("com.atproto.repo.listRecords", { params: { repo: "did:plc:test", collection: "x" } });
    } catch (err) {
      threw = String((err as Error).message);
    }
    assertEquals(threw.startsWith("token refresh: 400"), true, `expected the refresh failure, got: ${threw}`);
  } finally {
    await server.shutdown();
  }
});
