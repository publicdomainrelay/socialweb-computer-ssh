import { assertEquals, assertRejects } from "@std/assert";
import { fetchGuarded, isPrivateAddress, resolvesToPublicAddress } from "@publicdomainrelay/socialweb-computer-atproto";
import { isLogLine } from "@publicdomainrelay/socialweb-computer-request-vm-ssh";
import { requesterArgsFromEnv } from "@publicdomainrelay/socialweb-computer-common";

Deno.test("private and special addresses are recognised", () => {
  for (const address of [
    "127.0.0.1", "10.1.2.3", "172.16.0.1", "172.31.255.255", "192.168.1.1",
    "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1",
    "::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254",
  ]) {
    assertEquals(isPrivateAddress(address), true, `${address} should be private`);
  }
  for (const address of ["8.8.8.8", "1.1.1.1", "172.32.0.1", "2606:4700::1"]) {
    assertEquals(isPrivateAddress(address), false, `${address} should be public`);
  }
});

Deno.test("internal-looking hostnames are refused before any resolution", async () => {
  for (const host of ["localhost", "box.localhost", "db.internal", "printer.local", "127.0.0.1", "::1"]) {
    assertEquals(await resolvesToPublicAddress(host), false, `${host} should be refused`);
  }
});

Deno.test("fetchGuarded refuses a redirect rather than following it", async () => {
  const { promise, resolve } = Promise.withResolvers<number>();
  const server = Deno.serve({ port: 0, hostname: "127.0.0.1", onListen: (a) => resolve((a as Deno.NetAddr).port) }, (req) => {
    const url = new URL(req.url);
    if (url.pathname === "/redirect") return new Response(null, { status: 302, headers: { location: "https://example.com/elsewhere" } });
    if (url.pathname === "/big") return new Response("x".repeat(4096));
    return Response.json({ ok: true });
  });
  const port = await promise;
  try {
    assertEquals(JSON.parse((await fetchGuarded(`http://127.0.0.1:${port}/ok`, 1024))!), { ok: true });
    await assertRejects(() => fetchGuarded(`http://127.0.0.1:${port}/redirect`, 1024), Error, "redirect");
    await assertRejects(() => fetchGuarded(`http://127.0.0.1:${port}/big`, 1024), Error, "exceeded");
    assertEquals(await fetchGuarded(`http://169.254.169.254/latest/meta-data/`, 1024), null);
    assertEquals(await fetchGuarded("ftp://example.com/x", 1024), null);
  } finally {
    await server.shutdown();
  }
});

Deno.test("requester log lines are told apart from guest output", () => {
  assertEquals(isLogLine('{"ts":"2026-01-01T00:00:00.000Z","level":"info","message":"x"}'), true);
  assertEquals(isLogLine("plain command output"), false);
  assertEquals(isLogLine('{"argv":["run"],"exec":"echo hi"}'), false);
  assertEquals(isLogLine('{"ts":"now","level":"info"}'), false);
  assertEquals(isLogLine("{ not json"), false);
});

Deno.test("the door's environment is not handed to the client's requester", () => {
  // These configure request-vm-ssh through its own env fallback; a client must
  // not be able to reach them, and LC_KEEP_VM is gone entirely.
  assertEquals(requesterArgsFromEnv({ LC_KEEP_VM: "1" }), []);
  assertEquals(requesterArgsFromEnv({ SECRETS_FILE: "/secrets.json" }), []);
  assertEquals(requesterArgsFromEnv({ SSH_AUTHORIZED_KEY: "ssh-ed25519 AAAA" }), []);
});
