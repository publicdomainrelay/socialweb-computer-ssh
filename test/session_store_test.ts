import { assertEquals } from "@std/assert";
import { createFileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const DID = "did:plc:store";

function session(accessJwt: string, refreshJwt = "refresh"): OAuthSessionData {
  return {
    accessJwt,
    refreshJwt,
    userDid: DID,
    handle: "alice.test",
    pds: "https://pds.test",
    dpopPublicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    dpopPrivateJwk: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
  };
}

async function harness(): Promise<{
  path: string;
  store: ReturnType<typeof createFileSessionStore>;
  cleanup(): Promise<void>;
}> {
  const dir = await Deno.makeTempDir({ prefix: "swc-store-test-" });
  const path = `${dir}/oauth-sessions.json`;
  return {
    path,
    store: createFileSessionStore(path),
    cleanup: () => Deno.remove(dir, { recursive: true }).catch(() => {}),
  };
}

Deno.test("a corrupt store is quarantined, not silently emptied", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a1"));
    await Deno.writeTextFile(h.path, "{ this is not json");

    const corruptSeen: string[] = [];
    const store = createFileSessionStore(h.path, {
      onCorrupt: ({ quarantine }) => corruptSeen.push(quarantine),
    });

    // Reads as empty rather than wedging every request on a 500...
    assertEquals(await store.list(), []);
    assertEquals(corruptSeen.length, 1);
    // ...and the bytes are kept, so nothing is actually lost.
    assertEquals(await Deno.readTextFile(corruptSeen[0]), "{ this is not json");

    await store.set(DID, session("a2"));
    assertEquals((await store.get(DID))?.accessJwt, "a2");
  } finally {
    await h.cleanup();
  }
});

Deno.test("the session store is written owner-only", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a"));
    const mode = (await Deno.stat(h.path)).mode ?? 0;
    assertEquals(mode & 0o777, 0o600);
  } finally {
    await h.cleanup();
  }
});
