import { assertEquals, assertRejects } from "@std/assert";
import { createFileSessionStore, createFsOAuthSessionSource } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const DID = "did:plc:lease";
const OTHER = "did:plc:other";

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
  const dir = await Deno.makeTempDir({ prefix: "swc-lease-test-" });
  const path = `${dir}/oauth-sessions.json`;
  return {
    path,
    store: createFileSessionStore(path),
    cleanup: () => Deno.remove(dir, { recursive: true }).catch(() => {}),
  };
}

Deno.test("lease hands the account's session to the requester in a temp dir", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a1"));
    await h.store.set(OTHER, { ...session("b1"), userDid: OTHER });
    const source = createFsOAuthSessionSource({ sessionStore: h.store });

    await source.withSessionFor(DID, async ({ sessionPath }) => {
      const leased = JSON.parse(await Deno.readTextFile(sessionPath));
      assertEquals(leased.accessJwt, "a1");
      assertEquals(leased.dpopPrivateJwk.d, "d");
      assertEquals(sessionPath.includes("socialweb-computer-ssh-"), true);

      await Deno.writeTextFile(sessionPath, JSON.stringify(session("a2", "r2")));
      return undefined;
    });

    const stored = JSON.parse(await Deno.readTextFile(h.path));
    assertEquals(stored[DID].accessJwt, "a2");
    assertEquals(stored[DID].refreshJwt, "r2");
    assertEquals(stored[OTHER].accessJwt, "b1");
  } finally {
    await h.cleanup();
  }
});

Deno.test("lease removes its temp dir even when the requester throws", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a1"));
    const source = createFsOAuthSessionSource({ sessionStore: h.store });
    let seen = "";
    await assertRejects(
      () => source.withSessionFor(DID, async ({ sessionPath }) => {
        seen = sessionPath;
        throw new Error("requester exploded");
      }),
      Error,
      "requester exploded",
    );
    const dir = seen.split("/").slice(0, -1).join("/");
    await assertRejects(async () => { await Deno.stat(dir); }, Deno.errors.NotFound);
  } finally {
    await h.cleanup();
  }
});

Deno.test("lease refuses an account with no stored session", async () => {
  const h = await harness();
  try {
    const source = createFsOAuthSessionSource({ sessionStore: h.store });
    await assertRejects(
      () => source.withSessionFor(DID, async () => undefined),
      Error,
      `no oauth session stored for ${DID}`,
    );
  } finally {
    await h.cleanup();
  }
});

Deno.test("concurrent leases for different accounts do not clobber each other", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a1"));
    await h.store.set(OTHER, { ...session("b1"), userDid: OTHER });
    const source = createFsOAuthSessionSource({ sessionStore: h.store });

    await Promise.all([DID, OTHER].map((did, i) =>
      source.withSessionFor(did, async ({ sessionPath }) => {
        await Deno.writeTextFile(sessionPath, JSON.stringify({ ...session(`rotated-${i}`), userDid: did }));
      })
    ));

    const stored = JSON.parse(await Deno.readTextFile(h.path));
    assertEquals(stored[DID].accessJwt, "rotated-0");
    assertEquals(stored[OTHER].accessJwt, "rotated-1");
  } finally {
    await h.cleanup();
  }
});

Deno.test("two leases for one account serialize instead of losing a rotation", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a0"));
    const source = createFsOAuthSessionSource({ sessionStore: h.store });

    const seen: string[] = [];
    await Promise.all([0, 1].map((i) =>
      source.withSessionFor(DID, async ({ sessionPath }) => {
        const leased = JSON.parse(await Deno.readTextFile(sessionPath));
        seen.push(leased.accessJwt);
        await new Promise((r) => setTimeout(r, 20));
        await Deno.writeTextFile(sessionPath, JSON.stringify(session(`rotated-${i}`)));
      })
    ));

    assertEquals(seen, ["a0", "rotated-0"]);
    const stored = JSON.parse(await Deno.readTextFile(h.path));
    assertEquals(stored[DID].accessJwt, "rotated-1");
  } finally {
    await h.cleanup();
  }
});

Deno.test("a rotated session is kept even when the requester fails", async () => {
  const h = await harness();
  try {
    await h.store.set(DID, session("a0"));
    const source = createFsOAuthSessionSource({ sessionStore: h.store });
    await assertRejects(
      () => source.withSessionFor(DID, async ({ sessionPath }) => {
        await Deno.writeTextFile(sessionPath, JSON.stringify(session("rotated")));
        throw new Error("requester exploded");
      }),
      Error,
      "requester exploded",
    );
    const stored = JSON.parse(await Deno.readTextFile(h.path));
    assertEquals(stored[DID].accessJwt, "rotated");
  } finally {
    await h.cleanup();
  }
});

Deno.test("an unreadable store is an error, not an empty store", async () => {
  const h = await harness();
  try {
    await Deno.writeTextFile(h.path, "{ this is not json");
    await assertRejects(async () => { await h.store.list(); }, SyntaxError);
    await assertRejects(async () => { await h.store.set(DID, session("a")); }, SyntaxError);
    assertEquals(await Deno.readTextFile(h.path), "{ this is not json");
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
