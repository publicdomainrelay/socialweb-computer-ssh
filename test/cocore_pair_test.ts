import { assertEquals, assertNotEquals } from "@std/assert";
import { createJsonFileStore } from "@publicdomainrelay/json-file-store-fs";
import { createCocorePairing, sessionKey } from "@publicdomainrelay/socialweb-computer-cocore-http";
import type { CocoreToken } from "@publicdomainrelay/socialweb-computer-abc";

/**
 * The approved-poll response is documented but has never been observed -- the
 * only live probe reached co/core before the app's registration record existed,
 * so it was refused before an approval could happen. Everything after that point
 * is tested against this fake, which speaks the documented shape.
 */
function fakeAppview(polls: unknown[]) {
  let started = 0;
  let index = 0;
  const calls: { path: string; body: unknown }[] = [];

  const handler = async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    calls.push({ path: url.pathname + url.search, body: await req.clone().json().catch(() => null) });

    if (url.pathname.endsWith("devicePair.start")) {
      started += 1;
      return Response.json({
        deviceId: `dev-secret-${started}`,
        userCode: "ABCD-1234",
        verificationUri: "https://cocore.dev/device",
        pollIntervalSecs: 1,
        expiresInSecs: 600,
      });
    }
    if (url.pathname.endsWith("devicePair.poll")) {
      const next = polls[Math.min(index, polls.length - 1)];
      index += 1;
      return Response.json(next);
    }
    return new Response("not found", { status: 404 });
  };

  return { handler, calls };
}

async function withAppview<T>(
  polls: unknown[],
  fn: (opts: { apiBaseUrl: string; calls: { path: string; body: unknown }[] }) => Promise<T>,
): Promise<T> {
  const { handler, calls } = fakeAppview(polls);
  const { promise, resolve } = Promise.withResolvers<number>();
  const server = Deno.serve(
    { port: 0, hostname: "127.0.0.1", onListen: ({ port }) => resolve(port) },
    handler,
  );
  const port = await promise;
  try {
    return await fn({ apiBaseUrl: `http://127.0.0.1:${port}`, calls });
  } finally {
    await server.shutdown();
  }
}

function pairingFor(apiBaseUrl: string) {
  const dir = Deno.makeTempDirSync();
  const path = `${dir}/cocore-tokens.json`;
  const tokens = createJsonFileStore<CocoreToken>(path);
  const pairing = createCocorePairing({
    apiBaseUrl,
    tokens,
    appName: "socialweb-computer-ssh",
    appDid: "did:web:ssh.example.test",
    keyName: "socialweb-computer-ssh",
    returnUrl: "https://ssh.example.test/",
  });
  return { pairing, path, tokens };
}

const DID = "did:plc:alice";

Deno.test("sessionKey resolves the documented field and the two plausible others", () => {
  // The hedge, asserted so that removing a fallback fails loudly rather than
  // silently breaking whichever shape co/core actually sends.
  assertEquals(sessionKey({ apiKey: "cocore-a" }), "cocore-a");
  assertEquals(sessionKey({ token: "cocore-b" }), "cocore-b");
  assertEquals(sessionKey({ secret: "cocore-c" }), "cocore-c");
  assertEquals(sessionKey({ unrelated: "x" }), undefined);
  assertEquals(sessionKey({ apiKey: "" }), undefined);
});

Deno.test("a poll for a pairing that was never started reports expired", async () => {
  await withAppview([], async ({ apiBaseUrl }) => {
    const { pairing } = pairingFor(apiBaseUrl);
    assertEquals(await pairing.poll("no-such-pair-id"), "expired");
  });
});

Deno.test("start keeps the deviceId server-side and returns only the pairId", async () => {
  await withAppview([], async ({ apiBaseUrl }) => {
    const { pairing } = pairingFor(apiBaseUrl);
    const started = await pairing.start(DID);

    assertNotEquals(started.pairId, "");
    assertEquals(started.userCode, "ABCD-1234");
    assertEquals(started.verificationUri, "https://cocore.dev/device");
    assertEquals(started.intervalSecs, 1);

    const serialized = JSON.stringify(started);
    assertEquals(serialized.includes("dev-secret"), false, "the deviceId must not leave the process");
  });
});

Deno.test("a pending poll stores nothing", async () => {
  await withAppview([{ status: "pending" }], async ({ apiBaseUrl }) => {
    const { pairing } = pairingFor(apiBaseUrl);
    const { pairId } = await pairing.start(DID);

    assertEquals(await pairing.poll(pairId), "pending");
    assertEquals(await pairing.token(DID), undefined);
  });
});

Deno.test("an approved poll stores the key, mode 0600", async () => {
  await withAppview(
    [{ status: "pending" }, {
      status: "session",
      session: { did: "did:plc:cocore-user", handle: "alice", apiKey: "cocore-xyz", apiBase: "https://cocore.dev/api/v1" },
    }],
    async ({ apiBaseUrl }) => {
      const { pairing, path } = pairingFor(apiBaseUrl);
      const { pairId } = await pairing.start(DID);

      assertEquals(await pairing.poll(pairId), "pending");
      assertEquals(await pairing.poll(pairId), "complete");

      const stored = await pairing.token(DID);
      assertEquals(stored?.token, "cocore-xyz");
      assertEquals(stored?.accountDid, "did:plc:cocore-user");
      assertEquals(stored?.apiBase, "https://cocore.dev/api/v1");

      const mode = (await Deno.stat(path)).mode ?? 0;
      assertEquals(mode & 0o777, 0o600, "the token file must not be group- or world-readable");

      // A completed pairing is gone: polling the same id again is not a retry.
      assertEquals(await pairing.poll(pairId), "expired");
    },
  );
});

Deno.test("a denied poll stores nothing and does not wedge the account", async () => {
  await withAppview(
    [{ status: "denied" }, { status: "denied" }],
    async ({ apiBaseUrl }) => {
      const { pairing } = pairingFor(apiBaseUrl);
      const first = await pairing.start(DID);
      assertEquals(await pairing.poll(first.pairId), "denied");
      assertEquals(await pairing.token(DID), undefined);

      const second = await pairing.start(DID);
      assertNotEquals(second.pairId, first.pairId);
      assertEquals(await pairing.poll(second.pairId), "denied");
    },
  );
});

Deno.test("the start request names this deployment's app DID and return URL", async () => {
  await withAppview([], async ({ apiBaseUrl, calls }) => {
    const { pairing } = pairingFor(apiBaseUrl);
    await pairing.start(DID);

    const start = calls.find((c) => c.path.includes("devicePair.start"));
    assertEquals((start?.body as Record<string, unknown>)?.appDid, "did:web:ssh.example.test");
    assertEquals((start?.body as Record<string, unknown>)?.returnUrl, "https://ssh.example.test/");
  });
});
