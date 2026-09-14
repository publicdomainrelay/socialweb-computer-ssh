import { assert, assertEquals, assertRejects } from "@std/assert";
import { Hono } from "@hono/hono";
// @ts-types="npm:@types/ssh2@^1"
import { Client, utils, type ClientChannel } from "ssh2";
import { createAtprotoKeyAuthorizer } from "@publicdomainrelay/socialweb-computer-atproto";
import { createFileSessionStore, createFsOAuthSessionSource } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { createRequestVmSshRunner } from "@publicdomainrelay/socialweb-computer-request-vm-ssh";
import { createSshServer } from "@publicdomainrelay/socialweb-computer-ssh-ssh2";
import { BADGE_BLUE_KEYS_NSID, splitSshPublicKey } from "@publicdomainrelay/socialweb-computer-common";

const ACCOUNT_DID = "did:plc:testaccount0000000000000";
const STUB_REQUESTER = new URL("./fixtures/stub-requester.ts", import.meta.url).pathname;

interface Harness {
  sshPort: number;
  records: Array<Record<string, unknown>>;
  stateDir: string;
  setRecords(records: Array<Record<string, unknown>>): void;
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

async function startHarness(records: Array<Record<string, unknown>>): Promise<Harness> {
  const stateDir = await Deno.makeTempDir({ prefix: "socialweb-computer-ssh-test-" });
  let current = records;

  const pds = await serveApp(new Hono().get("/xrpc/com.atproto.repo.listRecords", (c) => {
    assertEquals(c.req.query("collection"), BADGE_BLUE_KEYS_NSID);
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
    config: { port: 0, hostname: "127.0.0.1", hostKeyPath: `${stateDir}/host_key` },
    authorizer: createAtprotoKeyAuthorizer({ plcDirectoryUrl: `http://127.0.0.1:${plc.port}`, cacheTtlMs: 0, negativeCacheTtlMs: 0 }),
    runner: createRequestVmSshRunner({
      requesterPath: STUB_REQUESTER,
      sessions: createFsOAuthSessionSource({ sessionStore }),
      denoExecutable: Deno.execPath(),
    }),
    defaultCommand: "bash",
    log: () => {},
  });
  const sshPort = await ssh.listen();

  return {
    sshPort,
    stateDir,
    get records() {
      return current;
    },
    setRecords(next) {
      current = next;
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
    assertEquals(summary.session.accessJwt, "access");
    assertEquals(summary.session.userDid, ACCOUNT_DID);
    assertEquals(summary.lcEnv, {});
    assertEquals(summary.sessionPath.startsWith("/"), true);
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
    await assertRejects(
      () => runOverSsh(harness.sshPort, stranger.privateKey, ACCOUNT_DID, "true"),
      Error,
      "All configured authentication methods failed",
    );
  } finally {
    await harness.close();
  }
});

Deno.test("ssh rejects an association whose challenge is another account", async () => {
  const authorized = keypair();
  const harness = await startHarness([
    associationRecord(authorized.publicKey, { challenge: "did:plc:someoneelse000000000000" }),
  ]);
  try {
    await assertRejects(
      () => runOverSsh(harness.sshPort, authorized.privateKey, ACCOUNT_DID, "true"),
      Error,
      "All configured authentication methods failed",
    );
  } finally {
    await harness.close();
  }
});

Deno.test("ssh rejects an association with the wrong service", async () => {
  const authorized = keypair();
  const harness = await startHarness([
    associationRecord(authorized.publicKey, { service: "bidder_associate" }),
  ]);
  try {
    await assertRejects(
      () => runOverSsh(harness.sshPort, authorized.privateKey, ACCOUNT_DID, "true"),
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
    await assertRejects(
      () => runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true"),
      Error,
      "All configured authentication methods failed",
    );
    harness.setRecords([associationRecord(key.publicKey)]);
    const result = await runOverSsh(harness.sshPort, key.privateKey, ACCOUNT_DID, "true");
    assertEquals(result.code, 0);
    assert(result.stdout.includes(ACCOUNT_DID));
  } finally {
    await harness.close();
  }
});
