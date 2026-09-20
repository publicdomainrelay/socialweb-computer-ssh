import { assertEquals } from "@std/assert";
import { createAtprotoSessionVerifier } from "@publicdomainrelay/socialweb-computer-oauth-atproto";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const DID = "did:plc:verifier";

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function dpopKeyPair(): Promise<{ publicJwk: Record<string, string>; privateJwk: Record<string, string> }> {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const priv = await crypto.subtle.exportKey("jwk", pair.privateKey);
  return { publicJwk: pub as Record<string, string>, privateJwk: priv as Record<string, string> };
}

function decodeProofPayload(dpop: string): Record<string, unknown> {
  const payload = dpop.split(".")[1];
  const padded = payload.replace(/-/g, "+").replace(/_/g, "/");
  return JSON.parse(atob(padded + "=".repeat((4 - (padded.length % 4)) % 4)));
}

async function withPds(
  handler: (req: Request) => Response,
  fn: (pds: string) => Promise<void>,
): Promise<void> {
  const { promise, resolve } = Promise.withResolvers<number>();
  const server = Deno.serve({ port: 0, hostname: "127.0.0.1", onListen: ({ port }) => resolve(port) }, handler);
  try {
    await fn(`http://127.0.0.1:${await promise}`);
  } finally {
    await server.shutdown();
  }
}

Deno.test("the verifier proves the session with a DPoP proof carrying ath", async () => {
  // RFC 9449 requires `ath` -- the base64url SHA-256 of the access token --
  // whenever a proof accompanies an access token. A real PDS rejects the proof
  // without it ("DPoP ath mismatch"), which is not something a hand-written
  // fake PDS notices unless it checks.
  const { publicJwk, privateJwk } = await dpopKeyPair();
  const accessJwt = "header.payload.signature";
  let seen: Record<string, unknown> | null = null;
  let seenAuth: string | null = null;

  await withPds((req) => {
    const dpop = req.headers.get("dpop");
    seenAuth = req.headers.get("authorization");
    if (dpop) seen = decodeProofPayload(dpop);
    return Response.json({ did: DID, handle: "alice.test" });
  }, async (pds) => {
    const verifier = createAtprotoSessionVerifier();
    const session: OAuthSessionData = {
      accessJwt,
      refreshJwt: "refresh",
      userDid: DID,
      handle: "alice.test",
      pds,
      dpopPublicJwk: publicJwk,
      dpopPrivateJwk: privateJwk,
    };
    const verified = await verifier.verify(session);
    assertEquals(verified?.did, DID);
  });

  // Assigned inside the handler closure, which control-flow analysis cannot see
  // through, so read them back through an explicit type.
  const proof = seen as Record<string, unknown> | null;
  const auth = seenAuth as string | null;

  assertEquals(auth, `DPoP ${accessJwt}`);
  const expected = b64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(accessJwt))));
  assertEquals(proof?.ath, expected, "the proof must carry ath = sha256(access token)");
  assertEquals(proof?.htm, "GET");
});

Deno.test("the verifier refuses a session whose PDS is not https or loopback", async () => {
  const { publicJwk, privateJwk } = await dpopKeyPair();
  const verifier = createAtprotoSessionVerifier();
  const verified = await verifier.verify({
    accessJwt: "a.b.c",
    refreshJwt: "refresh",
    userDid: DID,
    handle: "alice.test",
    pds: "http://evil.example.com",
    dpopPublicJwk: publicJwk,
    dpopPrivateJwk: privateJwk,
  });
  assertEquals(verified, null);
});

Deno.test("the verifier refuses a session the PDS attributes to another DID", async () => {
  const { publicJwk, privateJwk } = await dpopKeyPair();
  await withPds(() => Response.json({ did: "did:plc:someone-else", handle: "bob.test" }), async (pds) => {
    const verifier = createAtprotoSessionVerifier();
    const verified = await verifier.verify({
      accessJwt: "a.b.c",
      refreshJwt: "refresh",
      userDid: DID,
      handle: "alice.test",
      pds,
      dpopPublicJwk: publicJwk,
      dpopPrivateJwk: privateJwk,
    });
    assertEquals(verified, null);
  });
});
