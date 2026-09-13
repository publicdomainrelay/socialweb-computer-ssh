import { assertEquals, assertRejects } from "@std/assert";
import { createFileSessionStore, createFsOAuthSessionSource } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";

const DID = "did:plc:lease";
const OTHER = "did:plc:other";

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
    await h.store.store.set(DID, { tokenSet: { sub: DID, access_token: "a1" } } as never);
    await h.store.store.set(OTHER, { tokenSet: { sub: OTHER, access_token: "b1" } } as never);
    const source = createFsOAuthSessionSource({ sessionStore: h.store });

    await source.withSessionFor(DID, async ({ sessionPath }) => {
      const leased = JSON.parse(await Deno.readTextFile(sessionPath));
      assertEquals(Object.keys(leased), [DID]);
      assertEquals(leased[DID].tokenSet.access_token, "a1");
      assertEquals(sessionPath.includes("socialweb-computer-ssh-"), true);

      await Deno.writeTextFile(sessionPath, JSON.stringify({
        [DID]: { tokenSet: { sub: DID, access_token: "a2", refresh_token: "r2" } },
      }));
      return undefined;
    });

    const stored = JSON.parse(await Deno.readTextFile(h.path));
    assertEquals(stored[DID].tokenSet.access_token, "a2");
    assertEquals(stored[OTHER].tokenSet.access_token, "b1");
  } finally {
    await h.cleanup();
  }
});

Deno.test("lease removes its temp dir even when the requester throws", async () => {
  const h = await harness();
  try {
    await h.store.store.set(DID, { tokenSet: { sub: DID } } as never);
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
    await assertRejects(() => Deno.stat(dir), Deno.errors.NotFound);
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
    await h.store.store.set(DID, { tokenSet: { sub: DID, access_token: "a1" } } as never);
    await h.store.store.set(OTHER, { tokenSet: { sub: OTHER, access_token: "b1" } } as never);
    const source = createFsOAuthSessionSource({ sessionStore: h.store });

    await Promise.all([DID, OTHER].map((did, i) =>
      source.withSessionFor(did, async ({ sessionPath }) => {
        const leased = JSON.parse(await Deno.readTextFile(sessionPath));
        await Deno.writeTextFile(sessionPath, JSON.stringify({
          [did]: { tokenSet: { sub: did, access_token: `rotated-${i}` } },
        }));
        return leased;
      })
    ));

    const stored = JSON.parse(await Deno.readTextFile(h.path));
    assertEquals(stored[DID].tokenSet.access_token, "rotated-0");
    assertEquals(stored[OTHER].tokenSet.access_token, "rotated-1");
  } finally {
    await h.cleanup();
  }
});
