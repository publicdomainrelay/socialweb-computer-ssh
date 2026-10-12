import { assert, assertEquals } from "@std/assert";
// @ts-types="npm:@types/ssh2@^1"
import { Server, utils } from "ssh2";
import type { AddressInfo } from "node:net";
import type { CommandIo } from "@publicdomainrelay/socialweb-computer-abc";
import {
  contractUserData,
  createIrohSessionProvider,
  explainNoSession,
} from "@publicdomainrelay/socialweb-computer-requester-inproc";

const TICKET = "nodeabc4ticketxyz7";
const IROH_TARGET = `iroh://${TICKET}`;
const ROOT = new URL("../", import.meta.url).pathname;

function generateSshKey(): { private: string; public: string } {
  for (let attempt = 0; attempt < 20; attempt++) {
    const pair = utils.generateKeyPairSync("ed25519");
    if (!(utils.parseKey(pair.private) instanceof Error)) return pair;
  }
  throw new Error("ssh2 could not produce a parseable ed25519 key");
}

interface FakeGuest {
  port: number;
  closedConnections: () => number;
  close: () => Promise<void>;
}

function startFakeGuestSshd(): Promise<FakeGuest> {
  const hostKey = generateSshKey();
  let closed = 0;
  const server = new Server({ hostKeys: [hostKey.private] }, (client) => {
    client.on("authentication", (ctx) => ctx.method === "publickey" ? ctx.accept() : ctx.reject(["publickey"]));
    client.on("ready", () => {
      client.on("session", (acceptSession) => {
        const session = acceptSession();
        session.on("pty", (accept) => accept?.());
        session.on("exec", (accept, _reject, info) => {
          const stream = accept();
          if (info.command === "hang") return;
          stream.write(`ran:${info.command}\n`);
          stream.exit(0);
          stream.end();
        });
      });
    });
    client.on("close", () => {
      closed += 1;
    });
    client.on("error", () => {});
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      resolve({
        port: (server.address() as AddressInfo).port,
        closedConnections: () => closed,
        close: () => new Promise<void>((r) => server.close(() => r())),
      });
    });
  });
}

async function writeFakeDumbpipe(dir: string, port: number): Promise<{ path: string; calls: () => Promise<string[][]> }> {
  const path = `${dir}/dumbpipe`;
  const logPath = `${dir}/dumbpipe-calls.jsonl`;
  await Deno.writeTextFile(logPath, "");
  await Deno.writeTextFile(
    path,
    [
      "#!/usr/bin/env -S deno run -A --no-config",
      `await Deno.writeTextFile(${JSON.stringify(logPath)}, JSON.stringify(Deno.args) + "\\n", { append: true });`,
      `const conn = await Deno.connect({ hostname: "127.0.0.1", port: ${port} });`,
      "await Promise.race([Deno.stdin.readable.pipeTo(conn.writable), conn.readable.pipeTo(Deno.stdout.writable)]);",
      "",
    ].join("\n"),
  );
  await Deno.chmod(path, 0o755);
  return {
    path,
    calls: async () =>
      (await Deno.readTextFile(logPath)).split("\n").filter((l) => l.trim()).map((l) => JSON.parse(l) as string[]),
  };
}

function captureIo(): { io: CommandIo; out: () => string; err: () => string; closeInput: () => void } {
  const decoder = new TextDecoder();
  let out = "";
  let err = "";
  const closeHandlers: Array<() => void> = [];
  return {
    io: {
      write: (chunk) => {
        out += decoder.decode(chunk);
      },
      writeErr: (chunk) => {
        err += decoder.decode(chunk);
      },
      onData: () => {},
      onClose: (h) => {
        closeHandlers.push(h);
      },
      exit: () => {},
    },
    out: () => out,
    err: () => err,
    closeInput: () => closeHandlers.forEach((h) => h()),
  };
}

function forbidWebSocket(): { dialed: string[]; restore: () => void } {
  const original = globalThis.WebSocket;
  const dialed: string[] = [];
  globalThis.WebSocket = class {
    constructor(url: string | URL) {
      dialed.push(String(url));
      throw new Error(`websocket dial forbidden: ${url}`);
    }
  } as unknown as typeof WebSocket;
  return { dialed, restore: () => (globalThis.WebSocket = original) };
}

async function setup() {
  const guest = await startFakeGuestSshd();
  const dir = await Deno.makeTempDir({ prefix: "swc-iroh-test-" });
  const dumbpipe = await writeFakeDumbpipe(dir, guest.port);
  const clientKey = generateSshKey();
  const keyPath = `${dir}/id_ed25519`;
  await Deno.writeTextFile(keyPath, clientKey.private);
  const events: Array<{ event: string; data?: Record<string, unknown> }> = [];
  const log = (event: string, data?: Record<string, unknown>) => events.push({ event, data });
  const ws = forbidWebSocket();
  return {
    guest,
    dumbpipe,
    keyPath,
    events,
    log,
    ws,
    cleanup: async () => {
      ws.restore();
      await guest.close();
      await Deno.remove(dir, { recursive: true }).catch(() => {});
    },
  };
}

Deno.test("the requester asks for the iroh transport", () => {
  assertEquals(contractUserData(), { transport: "iroh" });
});

Deno.test("no source in socialweb-computer-ssh asks for a non-iroh transport or dials the websocket tunnel", async () => {
  const offenders: string[] = [];
  const forbidden = [
    /transport\s*:\s*["'`](?!iroh["'`])/,
    /tunnelWsUrl/,
    /sshTunnelArgs/,
    /com\.fedproxy\.temp\.xrpc\.tunnel/,
    /ensureWebsocat/,
    /new WebSocket\(/,
    /runSessionOverTunnel/,
  ];
  for (const top of ["lib", "hono-socialweb-computer-ssh"]) {
    const stack = [`${ROOT}${top}`];
    while (stack.length) {
      const dir = stack.pop()!;
      for await (const entry of Deno.readDir(dir)) {
        const path = `${dir}/${entry.name}`;
        if (entry.isDirectory) stack.push(path);
        else if (entry.name.endsWith(".ts")) {
          const text = await Deno.readTextFile(path);
          for (const re of forbidden) if (re.test(text)) offenders.push(`${path.slice(ROOT.length)} ${re}`);
        }
      }
    }
  }
  assertEquals(offenders, []);
});

Deno.test("the session provider dials through dumbpipe connect with the guest's ticket, never a websocket tunnel", async () => {
  const t = await setup();
  try {
    const cap = captureIo();
    const provider = createIrohSessionProvider({ io: cap.io, log: t.log, dumbpipePath: t.dumbpipe.path });
    assert(await provider.pollReady(t.keyPath, IROH_TARGET, 30_000), "guest should answer over the iroh dial");
    const code = await provider.runSession(t.keyPath, IROH_TARGET, "echo hello");
    assertEquals(code, 0);
    assert(cap.out().includes("ran:echo hello"), cap.out());
    const calls = await t.dumbpipe.calls();
    assert(calls.length >= 2, `dumbpipe dialed ${calls.length} times`);
    for (const argv of calls) assertEquals(argv, ["connect", TICKET]);
    assertEquals(t.ws.dialed, []);
  } finally {
    await t.cleanup();
  }
});

Deno.test("a guest address that is not an iroh ticket is refused without dialing anything", async () => {
  const t = await setup();
  try {
    const cap = captureIo();
    const provider = createIrohSessionProvider({ io: cap.io, log: t.log, dumbpipePath: t.dumbpipe.path });
    const started = Date.now();
    assertEquals(await provider.pollReady(t.keyPath, "vm--did-plc-x.relay.localhost:4433", 30_000), false);
    assert(Date.now() - started < 5_000, "refusal must not wait out the readiness timeout");
    assertEquals(await provider.runSession(t.keyPath, "vm--did-plc-x.relay.localhost:4433", "echo hi"), 1);
    assert(cap.err().includes("iroh"), cap.err());
    assertEquals(await t.dumbpipe.calls(), []);
    assertEquals(t.ws.dialed, []);
  } finally {
    await t.cleanup();
  }
});

Deno.test("vm.terminated ends a running guest session and closes the iroh dial", async () => {
  const t = await setup();
  try {
    const cap = captureIo();
    const provider = createIrohSessionProvider({ io: cap.io, log: t.log, dumbpipePath: t.dumbpipe.path });
    const ended = new AbortController();
    const session = provider.runSession(t.keyPath, IROH_TARGET, "hang", ended.signal);
    const startDeadline = Date.now() + 20_000;
    while (!t.events.some((e) => e.event === "guest_session_started") && Date.now() < startDeadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assert(t.events.some((e) => e.event === "guest_session_started"), JSON.stringify(t.events));
    const abortedAt = Date.now();
    ended.abort();
    const code = await session;
    assert(Date.now() - abortedAt < 5_000, "the session must end promptly on vm.terminated");
    assertEquals(code, 255);
    assert(t.events.some((e) => e.event === "guest_session_terminated"), JSON.stringify(t.events));
    const closeDeadline = Date.now() + 5_000;
    while (t.guest.closedConnections() < 1 && Date.now() < closeDeadline) {
      await new Promise((r) => setTimeout(r, 50));
    }
    assert(t.guest.closedConnections() >= 1, "the guest connection must be closed");
  } finally {
    await t.cleanup();
  }
});

Deno.test("vm.terminated stops the readiness poll", async () => {
  const t = await setup();
  try {
    await t.guest.close();
    const cap = captureIo();
    const provider = createIrohSessionProvider({ io: cap.io, log: t.log, dumbpipePath: t.dumbpipe.path });
    const ended = new AbortController();
    setTimeout(() => ended.abort(), 300);
    const started = Date.now();
    assertEquals(await provider.pollReady(t.keyPath, IROH_TARGET, 60_000, ended.signal), false);
    assert(Date.now() - started < 4_000, `poll took ${Date.now() - started}ms after vm.terminated`);
  } finally {
    await t.cleanup();
  }
});

Deno.test("a run the bidder terminated says so instead of a bare exit status", () => {
  const msg = explainNoSession(
    {
      event: "compute_request_complete",
      sshReady: false,
      terminated: { reason: "guest-gone", observedAt: "2026-10-12T00:00:00.000Z" },
    },
    { policy: "tangled-vouch", bidWindowSec: 30, vmReadyTimeoutSec: 300 },
  );
  assert(msg.includes("terminated"), msg);
  assert(msg.includes("guest-gone"), msg);
  assert(!msg.includes("did not come up"), msg);
});
