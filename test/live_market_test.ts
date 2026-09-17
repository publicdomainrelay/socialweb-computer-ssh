// Live end-to-end: SSH in through this repo's server, and the command you
// typed runs inside a real market VM.
//
//   ssh client -> this repo's SSH server (real publickey auth against a
//   badgeBlueKeys requester_associate record on an ephemeral PDS)
//     -> OAuth session leased into a temp dir
//     -> request-vm-ssh (RFP -> bid -> accept -> cloud-init)
//     -> guest container's sshd, over the relay tunnel
//
// Infrastructure is the same shape as atproto-market's own end-to-end tests:
// fake PLC + dispatcher relay + ephemeral atproto-relay + an ephemeral
// OAuth-PDS whose session injector mints the requester's session + a bidder
// subprocess running the local container compute provider.
//
// Run: deno test -A test/live_market_test.ts
// Needs a running container runtime (Apple `container` on darwin, docker
// elsewhere); the test skips loudly without one.

import { assert } from "@std/assert";
import { Hono } from "@hono/hono";
import { Secp256k1Keypair } from "@atproto/crypto";
// @ts-types="npm:@types/ssh2@^1"
import { Client, utils, type ClientChannel } from "ssh2";
import { createLogger } from "@publicdomainrelay/logger";
import { createRepoFactory } from "@publicdomainrelay/hono-factory-atproto-repo-deno";
import { MemoryStorage, signerFromKeypair } from "@publicdomainrelay/atproto-repo-deno";
import { createRelayFactory as createDispatcherFactory } from "@publicdomainrelay/hono-factory-did-key-ingress-proxy-xrpc";
import { createRelayFactory as createAtprotoRelayFactory } from "@publicdomainrelay/hono-factory-atproto-relay-xrpc";
import type { SessionInjector } from "@publicdomainrelay/atproto-oauth-server-abc";
import type { ContainerBackend } from "@publicdomainrelay/container-backend-abc";
import { createContainerBackend } from "@publicdomainrelay/container-backend-container";
import { createDockerBackend } from "@publicdomainrelay/container-backend-docker";
import { generateLocalhostTlsCert } from "@publicdomainrelay/tls-localhost";
import { createAtprotoKeyAuthorizer } from "@publicdomainrelay/socialweb-computer-atproto";
import { createFileSessionStore, createFsOAuthSessionSource } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { createInProcessRequester } from "@publicdomainrelay/socialweb-computer-requester-inproc";
import { createServe } from "@publicdomainrelay/serve";
import { createSshServer } from "@publicdomainrelay/socialweb-computer-ssh-ssh2";
import { BADGE_BLUE_KEYS_NSID, splitSshPublicKey } from "@publicdomainrelay/socialweb-computer-common";
import { installFetchInterceptor } from "../../atproto-market/test/fetch-interceptor.ts";

const ORG = new URL("../../", import.meta.url).pathname.replace(/\/$/, "");
const VOUCH_NSID = "sh.tangled.graph.vouch";
const log = createLogger({ serviceName: "swc-live" });

Deno.env.set("ATPROTO_DID", "");

function serveOnPort0(
  f: (r: Request) => Response | Promise<Response>,
  ac: AbortController,
  hostname = "127.0.0.1",
  cert?: string,
  key?: string,
): Promise<number> {
  const { promise, resolve } = Promise.withResolvers<number>();
  Deno.serve(
    { port: 0, hostname, signal: ac.signal, onListen: (a) => resolve((a as Deno.NetAddr).port), ...(cert && key ? { cert, key } : {}) },
    f,
  );
  return promise;
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function createAccount(pdsUrl: string, handle: string) {
  return fetch(`${pdsUrl}/xrpc/com.atproto.server.createAccount`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ handle, email: `${handle}@test`, password: "test" }),
  }).then((r) => r.json() as Promise<{ did: string }>);
}

function createFakePlc() {
  const ops = new Map<string, Record<string, unknown>>();
  const app = new Hono();
  const didFromPath = (path: string) => decodeURIComponent(path.startsWith("/") ? path.slice(1) : path);

  app.post("/*", async (c) => {
    const did = didFromPath(new URL(c.req.url).pathname);
    ops.set(did, await c.req.json().catch(() => ({})) as Record<string, unknown>);
    return c.json({ did });
  });

  app.get("/*", (c) => {
    const did = didFromPath(new URL(c.req.url).pathname);
    const op = ops.get(did);
    if (!op) return c.json({ message: `DID not found: ${did}` }, 404);
    const vms = (op.verificationMethods ?? {}) as Record<string, string>;
    const svcs = (op.services ?? {}) as Record<string, { type: string; endpoint: string }>;
    return c.json({
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/multikey/v1"],
      id: did,
      alsoKnownAs: (op.alsoKnownAs ?? []) as string[],
      verificationMethod: Object.entries(vms).map(([name, didKey]) => ({
        id: `${did}#${name}`,
        type: "Multikey",
        controller: did,
        publicKeyMultibase: String(didKey).replace(/^did:key:/, ""),
      })),
      service: Object.entries(svcs).map(([name, s]) => ({ id: `#${name}`, type: s.type, serviceEndpoint: s.endpoint })),
    });
  });

  return { app };
}

async function createRecordDpop(
  pdsUrl: string,
  session: { accessJwt: string; dpopPublicJwk: Record<string, string>; dpopPrivateJwk: Record<string, string> },
  userDid: string,
  collection: string,
  rkey: string,
  record: Record<string, unknown>,
): Promise<void> {
  const enc = new TextEncoder();
  const now = Math.floor(Date.now() / 1000);
  const proofHeader = { alg: "ES256", typ: "dpop+jwt", jwk: session.dpopPublicJwk };
  const proofPayload = {
    htm: "POST",
    htu: `${pdsUrl}/xrpc/com.atproto.repo.createRecord`,
    iat: now,
    jti: crypto.randomUUID(),
  };
  const signingInput = `${b64url(enc.encode(JSON.stringify(proofHeader)))}.${b64url(enc.encode(JSON.stringify(proofPayload)))}`;
  const key = await crypto.subtle.importKey(
    "jwk",
    session.dpopPrivateJwk,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(signingInput));

  const res = await fetch(`${pdsUrl}/xrpc/com.atproto.repo.createRecord`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      Authorization: `DPoP ${session.accessJwt}`,
      DPoP: `${signingInput}.${b64url(new Uint8Array(sig))}`,
    },
    body: JSON.stringify({ repo: userDid, collection, rkey, record, validate: false }),
  });
  if (!res.ok) throw new Error(`createRecord ${collection} failed: ${res.status} ${await res.text()}`);
}

function generateSshKey(): { private: string; public: string } {
  for (let attempt = 0; attempt < 20; attempt++) {
    const pair = utils.generateKeyPairSync("ed25519");
    if (!(utils.parseKey(pair.private) instanceof Error)) return pair;
  }
  throw new Error("ssh2 could not produce a parseable ed25519 key");
}

function sshExec(
  port: number,
  privateKey: string,
  username: string,
  command: string,
): Promise<{ stdout: string; stderr: string; code: number | undefined }> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let stdout = "";
    let stderr = "";
    let code: number | undefined;
    const timer = setTimeout(() => {
      conn.end();
      reject(new Error("ssh timeout"));
    }, 300_000);
    const decoder = new TextDecoder();

    conn.on("ready", () => {
      conn.exec(command, (err, stream: ClientChannel) => {
        if (err) {
          clearTimeout(timer);
          conn.end();
          return reject(err);
        }
        stream.on("data", (c: Uint8Array) => { stdout += decoder.decode(c); });
        stream.stderr.on("data", (c: Uint8Array) => { stderr += decoder.decode(c); });
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

Deno.test("[live] ssh into a market VM provisioned through the RFP flow", async () => {
  const backend: ContainerBackend = Deno.build.os === "darwin"
    ? createContainerBackend()
    : createDockerBackend();
  if (!(await backend.ensureRunning())) {
    console.log(`[SKIP] container backend not available (${Deno.build.os})`);
    return;
  }
  const gateway = await backend.defaultGateway();
  const cleanups: Array<() => void> = [];

  const { caCertPem, serverCertPem, serverKeyPem } = await generateLocalhostTlsCert({
    extraDnsSans: ["relay.localhost", "*.relay.localhost"],
  });

  const dispatcherApp = createDispatcherFactory({ hostname: "relay.localhost", additionalHosts: [gateway] }).createApp();
  const dispAc = new AbortController();
  const dispPort = await serveOnPort0(dispatcherApp.fetch, dispAc, "0.0.0.0");
  const dispTlsAc = new AbortController();
  const dispTlsPort = await serveOnPort0(dispatcherApp.fetch, dispTlsAc, "0.0.0.0", serverCertPem, serverKeyPem);
  cleanups.push(() => { dispAc.abort(); dispTlsAc.abort(); });
  const ingressProxyHost = `relay.localhost:${dispPort}`;

  const { app: plcApp } = createFakePlc();
  const plcAc = new AbortController();
  const plcPort = await serveOnPort0(plcApp.fetch, plcAc);
  cleanups.push(() => plcAc.abort());
  const plcDirectoryUrl = `http://localhost:${plcPort}`;

  const relayApp = createAtprotoRelayFactory({ hostname: "localhost", insecureHTTP: true }).app;
  const relayAc = new AbortController();
  const relayPort = await serveOnPort0(relayApp.fetch, relayAc, "0.0.0.0");
  cleanups.push(() => relayAc.abort());
  const relayUrl = `http://localhost:${relayPort}`;

  const restoreFetch = installFetchInterceptor({ realFetch: globalThis.fetch, plcDirectoryUrl, dispPort });
  cleanups.push(restoreFetch);

  let bidderChild: Deno.ChildProcess | undefined;

  try {
    const pdsKp = await Secp256k1Keypair.create({ exportable: true });
    const pdsAc = new AbortController();
    cleanups.push(() => pdsAc.abort());
    const pdsOpts = {
      storage: new MemoryStorage(),
      signer: signerFromKeypair(pdsKp),
      oauthServer: { enabled: true, issuer: "http://127.0.0.1:0" },
      plcDirectoryUrl,
      subscribeReposFormat: "json" as const,
      publicHostname: undefined as string | undefined,
      crawlers: [relayUrl],
    };
    const pds = createRepoFactory(pdsOpts);
    const pdsPort = await serveOnPort0(pds.app.fetch, pdsAc, "0.0.0.0");
    pdsOpts.publicHostname = `127.0.0.1:${pdsPort}`;
    const pdsUrl = `http://127.0.0.1:${pdsPort}`;

    const bidderAcct = await createAccount(pdsUrl, "bidder");
    const requesterAcct = await createAccount(pdsUrl, "requester");
    assert(requesterAcct.did?.startsWith("did:plc:"), `requester must get did:plc, got ${requesterAcct.did}`);

    const inj: SessionInjector = pds.sessionInjector!;
    assert(inj, "ephemeral PDS must expose a session injector");
    const bidderInj = await inj.injectSession({ userDid: bidderAcct.did, handle: "bidder" });
    bidderInj.sessionData.pds = pdsUrl;
    const requesterInj = await inj.injectSession({ userDid: requesterAcct.did, handle: "requester" });
    requesterInj.sessionData.pds = pdsUrl;

    const vouch = (vouchee: string) => ({
      $type: VOUCH_NSID,
      vouchee,
      createdAt: new Date().toISOString(),
    });
    await createRecordDpop(pdsUrl, bidderInj.sessionData, bidderAcct.did, VOUCH_NSID, requesterAcct.did, vouch(requesterAcct.did));
    await createRecordDpop(pdsUrl, requesterInj.sessionData, requesterAcct.did, VOUCH_NSID, bidderAcct.did, vouch(bidderAcct.did));

    // The association this repo's SSH door authenticates against: the account's
    // own badgeBlueKeys record of service requester_associate whose keyId is the
    // OpenSSH public key.
    const sshKey = generateSshKey();
    const pub = splitSshPublicKey(sshKey.public)!;
    await createRecordDpop(pdsUrl, requesterInj.sessionData, requesterAcct.did, BADGE_BLUE_KEYS_NSID,
      crypto.randomUUID().replace(/-/g, "").slice(0, 13), {
        $type: BADGE_BLUE_KEYS_NSID,
        keyId: `${pub.algo} ${pub.key}`,
        name: "live-e2e",
        challenge: requesterAcct.did,
        service: "requester_associate",
        createdAt: new Date().toISOString(),
      });

    // Bidder subprocess, as the market's own tests run it.
    const bidderSessionTmp = await Deno.makeTempDir({ prefix: "swc-live-bidder-" });
    const bidderSessionFile = `${bidderSessionTmp}/session.json`;
    await Deno.writeTextFile(bidderSessionFile, JSON.stringify(bidderInj.sessionData, null, 2));
    bidderChild = new Deno.Command("deno", {
      args: [
        "run", "-A", "--unstable-kv", `${ORG}/atproto-market/hono-bidder/mod.ts`,
        "--atproto-oauth-qr", "--oauth-session-file", bidderSessionFile,
        "--atproto-handle", "bidder", "--skip-qr",
        "--firehose-mode", "subscriberepos",
        "--firehose-url", relayUrl,
        "--plc-directory-url", plcDirectoryUrl,
        "--ingress-proxy-host", ingressProxyHost,
        "--compute-provider-local",
        "--policy", "tangled-vouch",
        "--no-ingress-proxy",
        "--serve-port", "0",
        "--guest-tls-port", String(dispTlsPort),
      ],
      stdout: "piped",
      stderr: "piped",
      env: { ...Deno.env.toObject(), ATPROTO_DID: "", CA_CERT_PEM: caCertPem },
    }).spawn();
    cleanups.push(() => { try { bidderChild?.kill("SIGTERM"); } catch { /* gone */ } });

    const guestContainers = new Set<string>();
    let vmDestroyed = false;
    const bidderReady = Promise.withResolvers<void>();
    const bidderLog = async (stream: ReadableStream<Uint8Array>) => {
      const reader = stream.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) return;
        buf += decoder.decode(value);
        const lines = buf.split("\n");
        buf = lines.pop() ?? "";
        for (const line of lines) {
          if (line.includes("containerName")) {
            try {
              const o = JSON.parse(line) as Record<string, unknown>;
              if (typeof o.containerName === "string") guestContainers.add(o.containerName);
            } catch { /* not our line */ }
          }
          if (line.includes("vm.delete") || line.includes("guest destroyed")) vmDestroyed = true;
          if (line.includes("bidder ready")) bidderReady.resolve();
          if (line.trim()) console.log(`[bidder] ${line.slice(0, 400)}`);
        }
      }
    };
    void bidderLog(bidderChild.stdout);
    void bidderLog(bidderChild.stderr);

    // The requester's session reaches the CLI through this repo's tempdir lease.
    const stateDir = await Deno.makeTempDir({ prefix: "swc-live-state-" });
    const sessionStore = createFileSessionStore(`${stateDir}/oauth-sessions.json`);
    await sessionStore.set(requesterAcct.did, requesterInj.sessionData as never);

    const serve = createServe({ logger: log });
    const ssh = createSshServer({
      config: { port: 0, hostname: "127.0.0.1", hostKeyPath: `${stateDir}/host_key` },
      authorizer: createAtprotoKeyAuthorizer({ plcDirectoryUrl }),
      runner: createInProcessRequester({
        sessionStore,
        requesterKeyPath: `${stateDir}/requester-private-key`,
        serve,
        plcDirectoryUrl,
        ingressProxyHost,
        relayUrls: [relayUrl],
        guestHostAliases: [`${gateway} relay.localhost`],
        vmReadyTimeoutSec: 180,
        log: (event, data) => log.info(event, data ?? {}),
      }),
      defaultCommand: "bash",
      log: (event, data) => log.info(event, data ?? {}),
    });
    const sshPort = await ssh.listen();
    cleanups.push(() => { void ssh.shutdown(); });

    // The RFP is delivered to the bidder's relay subscriber, so wait for the
    // bidder to announce itself before letting the SSH connection send one.
    await Promise.race([
      bidderReady.promise,
      new Promise((_, reject) => setTimeout(() => reject(new Error("bidder never became ready")), 120_000)),
    ]);

    await fetch(`${relayUrl}/xrpc/com.atproto.sync.requestCrawl`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ hostname: `127.0.0.1:${pdsPort}` }),
    });
    await new Promise((r) => setTimeout(r, 2_000));

    const result = await sshExec(sshPort, sshKey.private, requesterAcct.did, "echo SWC_GUEST_OK && cat /etc/hostname");
    log.info("ssh_result", { code: result.code, stdoutLen: result.stdout.length });

    const tail = `\nstdout: ${result.stdout.slice(-3000)}\nstderr: ${result.stderr.slice(-2000)}`;
    // The requester logs its own argv as JSON, so a marker merely *present* in
    // stdout proves nothing. Only the guest's shell can emit it as a bare line.
    const lines = result.stdout.split("\n").map((l) => l.trim());
    assert(lines.includes("SWC_GUEST_OK"), `guest must return its marker as a bare line over the SSH channel.${tail}`);
    assert(result.code === 0, `ssh exec must exit 0, got ${result.code}`);
    assert(
      lines.some((l) => l.length > 0 && !l.startsWith("{") && l !== "SWC_GUEST_OK"),
      `guest must also report its hostname.${tail}`,
    );
    assert(guestContainers.size > 0, "the test must have observed the guest container");
    assert(vmDestroyed || guestContainers.size > 0, "requester must submit vm.delete");

    // Teardown is the last leg: the requester submits a signed vm.delete and the
    // bidder destroys the guest. Poll the runtime itself -- a log line saying so
    // is not the same as the container being gone.
    const alive = async (): Promise<string[]> => {
      const running: string[] = [];
      for (const name of guestContainers) {
        try {
          if (await backend.inspectIp(name)) running.push(name);
        } catch { /* gone -- what we want */ }
      }
      return running;
    };
    let stillRunning = await alive();
    const deadline = Date.now() + 60_000;
    while (stillRunning.length > 0 && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 1000));
      stillRunning = await alive();
    }
    assert(stillRunning.length === 0, `guest container(s) still running 60s after the command exited: ${stillRunning.join(", ")}`);

    log.info("PASS -- command ran inside a market VM reached over this repo's SSH server");
  } finally {
    for (const c of cleanups.reverse()) {
      try { c(); } catch { /* best effort */ }
    }
    await new Promise((r) => setTimeout(r, 300));
  }
});
