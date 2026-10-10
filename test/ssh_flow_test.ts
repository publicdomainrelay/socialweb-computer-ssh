import { assert, assertEquals, assertRejects } from "@std/assert";
import { Hono } from "@hono/hono";
// @ts-types="npm:@types/ssh2@^1"
import { Client, utils, type ClientChannel } from "ssh2";
import { createAtprotoKeyAuthorizer } from "@publicdomainrelay/socialweb-computer-atproto";
import { createFileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { renderExecCommand } from "@publicdomainrelay/socialweb-computer-common";
import type { ComputeCommandRunner } from "@publicdomainrelay/socialweb-computer-abc";
import { createSshServer } from "@publicdomainrelay/socialweb-computer-ssh-ssh2";
import { BADGE_BLUE_KEYS_NSID, splitSshPublicKey } from "@publicdomainrelay/socialweb-computer-common";

const ACCOUNT_DID = "did:plc:testaccount0000000000000";
// A fake runner: this test covers the SSH plumbing, not provisioning. It reports
// the same fields the spawned stub requester used to echo from its argv.
function fakeRequester(): ComputeCommandRunner {
  return {
    async run(account, command, env, io): Promise<void> {
      const { policyFromEnv } = await import("@publicdomainrelay/socialweb-computer-common");
      const { policy, args } = policyFromEnv(env);
      await io.write(new TextEncoder().encode(JSON.stringify({
        accountDid: account.did,
        policy,
        policyArgs: args,
        exec: renderExecCommand(command, env),
        lcEnv: Object.fromEntries(Object.entries(env).filter(([k]) => k.startsWith("LC_"))),
      }) + "\n"));
      const exit = /--stub-exit (\d+)/.exec(command);
      io.exit(exit ? Number(exit[1]) : 0);
    },
  };
}

interface Harness {
  sshPort: number;
  records: Array<Record<string, unknown>>;
  logs: Array<{ event: string; data?: Record<string, unknown> }>;
  stateDir: string;
  setRecords(records: Array<Record<string, unknown>>): void;
  failLookups(): void;
  close(): Promise<void>;
}

interface SshResult {
  stdout: string;
  stderr: string;
  code: number | undefined;
}

async function serveApp(app: Hono): Promise<{ port: number; close(): Promise<void> }> {
  const { promise, resolve } = Promise.withResolvers<number>();
  const server = Deno.serve({ port: 0, hostname: "127.0.0.1", onListen: (addr) => resolve(addr.port) }, app.fetch);
  const port = await promise;
  return { port, close: () => server.shutdown() };
}

async function startHarness(
  records: Array<Record<string, unknown>>,
  configOverride: Record<string, unknown> = {},
  runner: ComputeCommandRunner = fakeRequester(),
): Promise<Harness> {
  const stateDir = await Deno.makeTempDir({ prefix: "socialweb-computer-ssh-test-" });
  const logs: Array<{ event: string; data?: Record<string, unknown> }> = [];
  let current = records;
  let pdsFailing = false;

  const pds = await serveApp(new Hono().get("/xrpc/com.atproto.repo.listRecords", (c) => {
    assertEquals(c.req.query("collection"), BADGE_BLUE_KEYS_NSID);
    if (pdsFailing) return c.json({ error: "boom" }, 500);
    return c.json({
      records: current.map((value, i) => ({
        uri: `at://${ACCOUNT_DID}/${BADGE_BLUE_KEYS_NSID}/${i}`,
        cid: `cid${i}`,
        value,
      })),
    });
  }));

  const plc = await serveApp(new Hono().get("/*", (c) => {
    const did = decodeURIComponent(new URL(c.req.url).pathname.slice(1));
    if (did !== ACCOUNT_DID) return c.json({ message: "not found" }, 404);
    return c.json({
      "@context": ["https://www.w3.org/ns/did/v1"],
      id: ACCOUNT_DID,
      alsoKnownAs: ["at://alice.test"],
      verificationMethod: [],
      service: [{
        id: "#atproto_pds",
        type: "AtprotoPersonalDataServer",
        serviceEndpoint: `http://127.0.0.1:${pds.port}`,
      }],
    });
  }));

  const sessionStore = createFileSessionStore(`${stateDir}/oauth-sessions.json`);
  await sessionStore.set(ACCOUNT_DID, {
    accessJwt: "access",
    refreshJwt: "refresh",
    userDid: ACCOUNT_DID,
    handle: "alice.test",
    pds: "https://pds.test",
    dpopPublicJwk: { kty: "EC", crv: "P-256", x: "x", y: "y" },
    dpopPrivateJwk: { kty: "EC", crv: "P-256", x: "x", y: "y", d: "d" },
  });

  const ssh = createSshServer({
    config: { port: 0, hostname: "127.0.0.1", hostKeyPath: `${stateDir}/host_key`, ...configOverride },
    authorizer: createAtprotoKeyAuthorizer({ plcDirectoryUrl: `http://127.0.0.1:${plc.port}`, cacheTtlMs: 0, negativeCacheTtlMs: 0 }),
    runner,
    defaultCommand: "bash",
    log: (event, data) => { logs.push({ event, data }); },
  });
  const sshPort = await ssh.listen();

  return {
    sshPort,
    stateDir,
    logs,
    get records() {
      return current;
    },
    setRecords(next) {
      current = next;
    },
    failLookups() {
      pdsFailing = true;
    },
    async close() {
      await ssh.shutdown();
      await pds.close();
      await plc.close();
      await Deno.remove(stateDir, { recursive: true }).catch(() => {});
    },
  };
}

function runOverSsh(
  port: number,
  privateKey: string,
  username: string,
  command: string,
  env: Record<string, string> = {},
): Promise<SshResult> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let stdout = "";
    let stderr = "";
    let code: number | undefined;
    const timer = setTimeout(() => reject(new Error("ssh timeout")), 30_000);

    conn.on("ready", () => {
      conn.exec(command, { env }, (err, stream) => {
        if (err) {
          clearTimeout(timer);
          conn.end();
          return reject(err);
        }
        collect(stream, (s) => { stdout += s; }, (s) => { stderr += s; });
        stream.on("exit", (c: number) => { code = c; });
        stream.on("close", () => {
          clearTimeout(timer);
          conn.end();
          resolve({ stdout, stderr, code });
        });
      });
    });
    conn.on("error", (err: Error) => {
      clearTimeout(timer);
      reject(err);
    });
    conn.connect({ host: "127.0.0.1", port, username, privateKey, hostVerifier: () => true });
  });
}

function collect(stream: ClientChannel, onOut: (s: string) => void, onErr: (s: string) => void): void {
  const decoder = new TextDecoder();
  stream.on("data", (chunk: Uint8Array) => onOut(decoder.decode(chunk)));
  stream.stderr.on("data", (chunk: Uint8Array) => onErr(decoder.decode(chunk)));
}

// ssh2's key generator occasionally emits a private key it cannot itself
// re-parse. Retry until it produces one that works, rather than letting a flake
// surface as an authentication failure.
function keypair(): { privateKey: string; publicKey: string } {
  for (let attempt = 0; attempt < 20; attempt++) {
    const pair = utils.generateKeyPairSync("ed25519");
    if (!(utils.parseKey(pair.private) instanceof Error)) {
      return { privateKey: pair.private, publicKey: pair.public };
    }
  }
  throw new Error("ssh2 could not produce a parseable ed25519 key");
}

function associationRecord(publicKey: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const parsed = splitSshPublicKey(publicKey)!;
  return {
    $type: BADGE_BLUE_KEYS_NSID,
    keyId: `${parsed.algo} ${parsed.key}`,
    name: "test-key",
    challenge: ACCOUNT_DID,
    service: "requester_associate",
    createdAt: new Date().toISOString(),
    ...overrides,
  };
}

Deno.test("ssh exec runs the requester with defaults and forwards LC_ env", async () => {
  const authorized = keypair();
  const harness = await startHarness([associationRecord(authorized.publicKey)]);
  try {
    const result = await runOverSsh(
      harness.sshPort,
      authorized.privateKey,
      ACCOUNT_DID,
      "echo $LC_MY_VAR",
      { LC_MY_VAR: "secret_value" },
    );
    assertEquals(result.code, 0);
    const summary = JSON.parse(result.stdout.trim());
    assertEquals(summary.accountDid, ACCOUNT_DID);
    assertEquals(summary.policy, "tangled-vouch");
    assertEquals(summary.policyArgs, { firstFree: true });
    assertEquals(summary.exec, "export LC_MY_VAR='secret_value'; echo $LC_MY_VAR");
    // In-process there is no child environment for LC_ vars to leak into, so
    // they reach the runner directly -- and non-LC vars still do not.
    assertEquals(summary.lcEnv, { LC_MY_VAR: "secret_value" });
  } finally {
    await harness.close();
  }
});

Deno.test("ssh exec accepts LC_ policy overrides and keeps non-LC env out", async () => {
  const authorized = keypair();
  const harness = await startHarness([associationRecord(authorized.publicKey)]);
  try {
    const result = await runOverSsh(
      harness.sshPort,
      authorized.privateKey,
      ACCOUNT_DID,
      "true",
      { LC_POLICY: "only-me", LC_POLICY_FIRST_FREE: "false", LC_POLICY_BID_WINDOW_SEC: "7", SECRET_TOKEN: "leak" },
    );
    const summary = JSON.parse(result.stdout.trim());
    assertEquals(summary.policy, "only-me");
    assertEquals(summary.policyArgs, { firstFree: false, bidWindowSec: 7 });
    assertEquals(summary.exec, "export LC_POLICY='only-me' LC_POLICY_FIRST_FREE='false' LC_POLICY_BID_WINDOW_SEC='7'; true");
  } finally {
    await harness.close();
  }
});

Deno.test("ssh rejects a key with no requester_associate record", async () => {
  const authorized = keypair();
  const stranger = keypair();
  const harness = await startHarness([associationRecord(authorized.publicKey)]);
  try {
    // Rejection, not acceptance. ssh offers keys in order and stops at the first
    // the server accepts, so accepting this stranger's key would end
    // authentication before the client reached any key that is associated --
    // which is exactly how a correctly-registered account got locked out.
    await assertRejects(
      () => runOverSsh(harness.sshPort, stranger.privateKey, ACCOUNT_DID, "true"),
      Error,
      "All configured authentication methods failed",
    );
  } finally {
    await harness.close();
  }
});



Deno.test("ssh shell request runs the default command", async () => {
  const authorized = keypair();
  const harness = await startHarness([associationRecord(authorized.publicKey)]);
  try {
    const result = await new Promise<SshResult>((resolve, reject) => {
      const conn = new Client();
      let stdout = "";
      const timer = setTimeout(() => reject(new Error("ssh timeout")), 30_000);
      conn.on("ready", () => {
        (conn as unknown as { shell(w: false, cb: (e: Error | null, s: ClientChannel) => void): void }).shell(
          false,
          (err, stream) => {
            if (err) {
              clearTimeout(timer);
              conn.end();
              return reject(err);
            }
            collect(stream, (chunk) => { stdout += chunk; }, () => {});
            stream.on("close", () => {
              clearTimeout(timer);
              conn.end();
              resolve({ stdout, stderr: "", code: 0 });
            });
          },
        );
      });
      conn.on("error", reject);
      conn.connect({
        host: "127.0.0.1",
        port: harness.sshPort,
        username: ACCOUNT_DID,
        privateKey: authorized.privateKey,
        hostVerifier: () => true,
      });
    });
    assertEquals(JSON.parse(result.stdout.trim()).exec, "bash");
  } finally {
    await harness.close();
  }
});

Deno.test("ssh propagates the requester's exit code", async () => {
  const authorized = keypair();
  const harness = await startHarness([associationRecord(authorized.publicKey)]);
  try {
    const result = await runOverSsh(
      harness.sshPort,
      authorized.privateKey,
      ACCOUNT_DID,
      `--stub-exit 7`,
    );
    assertEquals(result.code, 7);
  } finally {
    await harness.close();
  }
});

Deno.test("newly registered association is honored after the cache window", async () => {
  const key = keypair();
  const harness = await startHarness([]);
  try {
    // No associations yet, so no key could match: the door explains rather than
    // refusing, and exits non-zero without running anything.
    const beforeRegistration = await runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true");
    assertEquals(beforeRegistration.code, 1);
    assert(!beforeRegistration.stdout.includes(ACCOUNT_DID));
    harness.setRecords([associationRecord(key.publicKey)]);
    const result = await runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true");
    assertEquals(result.code, 0);
    assert(result.stdout.includes(ACCOUNT_DID));
  } finally {
    await harness.close();
  }
});

Deno.test("shutdown finishes while a client is still connected", async () => {
  // A restart closes the listening socket first, so a shutdown that waits on an
  // open session leaves the door down rather than merely slow: which is what
  // "deactivating"/"stop-sigterm" was, with port 22 already closed. A client
  // that connects and then sits there is the ordinary case, not an attack.
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)]);
  const conn = new Client();
  try {
    await new Promise<void>((resolve, reject) => {
      conn
        .on("ready", () => resolve())
        .on("error", reject)
        .connect({
          host: "127.0.0.1",
          port: harness.sshPort,
          username: ACCOUNT_DID,
          privateKey: key.privateKey,
          hostVerifier: () => true,
        });
    });

    // Raced so a regression fails the test rather than wedging the runner, and
    // timed because completion alone is too weak an assertion: shutdown is
    // bounded by a grace period anyway, so "it finished" would also pass if the
    // server merely waited that grace out instead of ending this session.
    const started = Date.now();
    const finished = await Promise.race([
      harness.close().then(() => true),
      new Promise<boolean>((resolve) => setTimeout(() => resolve(false), 15_000)),
    ]);
    const elapsed = Date.now() - started;
    assert(finished, "shutdown never completed with a session still connected");
    assert(
      elapsed < 4_000,
      `shutdown waited ${elapsed}ms, so it did not end the open session -- it timed out`,
    );
  } finally {
    try {
      conn.end();
    } catch { /* already gone */ }
  }
});

Deno.test("a failed association lookup is not reported as an unassociated key", async () => {
  // The authorizer returns null for "no association" and, before this, also for
  // "the lookup itself broke" -- a timeout, a refused fetch, a DNS blip. Saying
  // "not associated" on the strength of a failed lookup is a false claim about
  // the caller's key, and it sends someone who is correctly registered off to
  // register again. A broken lookup must refuse the connection instead.
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)]);
  try {
    harness.failLookups();
    await assertRejects(
      () => runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true"),
      Error,
      "All configured authentication methods failed",
    );
  } finally {
    await harness.close();
  }
});

Deno.test("an account that cannot be resolved is not reported as an unassociated key", async () => {
  // The identity resolver returns nothing for a handle it cannot look up, the
  // same as for one that does not exist -- it does not throw. Treating that as
  // "no association" is the same false claim as a failed fetch, and it is what
  // turned a DNS blip at startup into an accusation against a valid key.
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)]);
  try {
    await assertRejects(
      () => runOverSsh(harness.sshPort, key.privateKey, "did:plc:noaccounthere000000000000", "true"),
      Error,
      "All configured authentication methods failed",
    );
  } finally {
    await harness.close();
  }
});

Deno.test("an account with no requester association is told so instead of refused", async () => {
  // No key the caller holds could match, so there is no later key to pre-empt:
  // accepting to explain costs nothing here, and refusing would leave them with
  // "Permission denied (publickey)" and no idea that the association is missing.
  const stranger = keypair();
  const harness = await startHarness([]);
  try {
    const result = await runOverSsh(harness.sshPort, stranger.privateKey, ACCOUNT_DID, "true");
    assertEquals(result.code, 1);
    assert(result.stderr.includes("can sign in here"));
    assert(!result.stdout.includes(ACCOUNT_DID), "nothing may run without an account");
  } finally {
    await harness.close();
  }
});

Deno.test("an association challenging another account counts as none for this one", async () => {
  const authorized = keypair();
  const harness = await startHarness([
    associationRecord(authorized.publicKey, { challenge: "did:plc:someoneelse000000000000" }),
  ]);
  try {
    const result = await runOverSsh(harness.sshPort, authorized.privateKey, ACCOUNT_DID, "true");
    assertEquals(result.code, 1);
    assert(result.stderr.includes("can sign in here"));
  } finally {
    await harness.close();
  }
});

Deno.test("a username that is not a handle is told so without a lookup", async () => {
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)]);
  try {
    const result = await runOverSsh(harness.sshPort, key.privateKey, "someuser", "true");
    assertEquals(result.code, 1);
    assert(result.stderr.includes("can sign in here"));
  } finally {
    await harness.close();
  }
});

function hangingRunner(): ComputeCommandRunner {
  return { run: () => new Promise<void>(() => {}) };
}

Deno.test("the door writes nothing of its own to the session channel", async () => {
  // A session channel carries the guest's command and nothing else. The door used
  // to open stderr with a machine-readable deadline line, for a reader in another
  // repo that no longer exists; every consumer of it is gone, so the line was a
  // log line in a place logs do not belong - a human's terminal - on every
  // connection. The deadline is the door's own business and lives in its log.
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)], { sessionMaxSec: 30 });
  try {
    const token = "sk-supersecrettokenvalue";
    const result = await runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, `--token ${token}`);
    assert(
      !result.stderr.includes("session-report"),
      `the door wrote its own line to the session: ${JSON.stringify(result.stderr)}`,
    );
    assert(
      !result.stdout.includes("session-report"),
      `the door wrote its own line to the session: ${JSON.stringify(result.stdout)}`,
    );
    // stdout is the harness's own echo of the run request, which necessarily
    // names the command; stderr is where only the guest and the door write.
    assert(!result.stderr.includes(token), `the token reached the session's stderr: ${result.stderr}`);
    const started = harness.logs.find((l) => l.event === "session_started");
    assert(started !== undefined, "the door did not log the session's start");
    const logged = JSON.stringify(started.data ?? {});
    // The deadline is still recorded where a machine reads it: the door's log.
    assert(logged.includes("remainingSec"), `the log line carries no deadline: ${logged}`);
    for (const { event, data } of harness.logs) {
      const text = `${event} ${JSON.stringify(data ?? {})}`;
      assert(!text.includes(token), `the token reached a log line: ${text}`);
      assert(!/\benv\b/.test(text), `a log line carries the session env: ${text}`);
      assert(!/\bcommand\b/.test(text), `a log line carries the command: ${text}`);
    }
  } finally {
    await harness.close();
  }
});

Deno.test("the session cap ends a session that outlives it", async () => {
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)], { sessionMaxSec: 1 }, hangingRunner());
  try {
    const started = Date.now();
    const result = await runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true");
    const elapsed = Date.now() - started;
    assertEquals(result.code, 1);
    assert(elapsed >= 900, `session ended after ${elapsed}ms, before its own 1s cap`);
    assert(elapsed < 10_000, `session outlived its 1s cap by ${elapsed}ms`);
    assertEquals(harness.logs.filter((l) => l.event === "session_capped").length, 1);
  } finally {
    await harness.close();
  }
});

Deno.test("a zero cap means the door never ends the session", async () => {
  const key = keypair();
  const harness = await startHarness([associationRecord(key.publicKey)], { sessionMaxSec: 0 }, hangingRunner());
  try {
    // "Unlimited" is only honest while nothing kills the session: a timer armed
    // for a reported 0 would make the report a guess.
    const outcome = await Promise.race([
      runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true").then(() => "ended"),
      new Promise<string>((resolve) => setTimeout(() => resolve("still open"), 2_500)),
    ]);
    assertEquals(outcome, "still open");
    assertEquals(harness.logs.some((l) => l.event === "session_capped"), false);
  } finally {
    await harness.close();
  }
});

Deno.test("no log call in the door can carry the command or the session env", async () => {
  const source = await Deno.readTextFile(
    new URL("../lib/socialweb-computer-ssh-ssh2/mod.ts", import.meta.url),
  );
  const calls = [...source.matchAll(/\blog\(\s*"([a-z_]+)"\s*,\s*\{([^}]*)\}/g)];
  // A call the pattern cannot read is a call this test cannot see, so a shape it
  // does not recognise fails here rather than passing unexamined.
  assertEquals(
    calls.length,
    [...source.matchAll(/\blog\(/g)].length,
    "a log call is shaped so that this guard cannot read it",
  );
  assert(calls.length > 0, "expected the door to log something");
  for (const [, event, fields] of calls) {
    for (const field of fields.split(",")) {
      const [name, ...value] = field.split(":");
      const expression = value.join(":").trim();
      assert(!/\benv\b/.test(expression), `${event} logs the session env as ${name}`);
      assert(
        !/\bcommand\b/.test(expression) || expression === "command.length",
        `${event} logs the command as ${name}`,
      );
    }
  }
});
