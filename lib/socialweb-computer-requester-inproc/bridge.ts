// @ts-types="npm:@types/ssh2@^1"
import { Buffer } from "node:buffer";
import { Duplex } from "node:stream";
import { Client } from "ssh2";
import { dumbpipeConnectArgv } from "@publicdomainrelay/requester-xrpc";
import type { GuestHostKeys, SshSessionProvider } from "@publicdomainrelay/requester-abc";
import type { CommandIo } from "@publicdomainrelay/socialweb-computer-abc";

export type GatewayLog = (event: string, data?: Record<string, unknown>) => void;

export const TERMINATED_SESSION_EXIT_CODE = 255;

const POLL_INTERVAL_MS = 5_000;

export class NonIrohGuestAddressError extends Error {
  constructor(readonly target: string) {
    super(`guest address is not an iroh ticket (iroh://...): ${target}`);
  }
}

export class GuestHostKeyMismatchError extends Error {
  constructor(readonly alias: string) {
    super(`the guest's ssh host key is not the one it reported (${alias}); refusing to authenticate`);
  }
}

export class MissingGuestHostKeysError extends Error {
  constructor(readonly target: string) {
    super(`no reported ssh host key for ${target}; refusing to connect without one`);
  }
}

function reportedKeySet(hostKeys: GuestHostKeys): Set<string> {
  return new Set(hostKeys.keys.map((k) => k.publicKey));
}

interface IrohDial {
  sock: Duplex;
  close(): void;
}

function dialIroh(target: string, dumbpipePath: string, log: GatewayLog): IrohDial {
  const argv = dumbpipeConnectArgv(target, dumbpipePath);
  if (!argv) throw new NonIrohGuestAddressError(target);
  const child = new Deno.Command(argv[0], {
    args: argv.slice(1),
    stdin: "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let killed = false;
  const kill = () => {
    if (killed) return;
    killed = true;
    try {
      child.kill("SIGTERM");
    } catch {
      return;
    }
  };
  const writer = child.stdin.getWriter();
  const sock = new Duplex({
    read() {},
    write(chunk: Uint8Array, _encoding, cb) {
      writer.write(new Uint8Array(chunk)).then(() => cb(), (err) => cb(err as Error));
    },
    final(cb) {
      writer.close().then(() => cb(), () => cb());
    },
    destroy(err, cb) {
      kill();
      cb(err);
    },
  });
  void (async () => {
    for await (const chunk of child.stdout) sock.push(chunk);
    sock.push(null);
  })().catch((err) => sock.destroy(err as Error));
  void (async () => {
    const decoder = new TextDecoder();
    let tail = "";
    for await (const chunk of child.stderr) tail = (tail + decoder.decode(chunk)).slice(-2000);
    const status = await child.status;
    if (!killed && !status.success) log("guest_iroh_dial_exit", { code: status.code, stderr: tail.trim() });
  })().catch(() => {});
  return { sock, close: kill };
}

async function connect(
  target: string,
  dumbpipePath: string,
  privateKey: string,
  timeoutMs: number,
  log: GatewayLog,
  hostKeys: GuestHostKeys,
  signal?: AbortSignal,
): Promise<{ client: Client; dial: IrohDial }> {
  const accepted = reportedKeySet(hostKeys);
  let mismatch = false;
  const dial = dialIroh(target, dumbpipePath, log);
  const client = new Client();
  try {
    await new Promise<void>((resolve, reject) => {
      const onAbort = () => reject(new Error("guest terminated while connecting"));
      if (signal?.aborted) return onAbort();
      signal?.addEventListener("abort", onAbort, { once: true });
      const timer = setTimeout(() => reject(new Error("iroh connect timed out")), timeoutMs);
      const settle = () => {
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
      };
      client
        .on("ready", () => {
          settle();
          resolve();
        })
        .on("error", (err: Error) => {
          settle();
          reject(mismatch ? new GuestHostKeyMismatchError(hostKeys.alias) : err);
        })
        .connect({
          sock: dial.sock,
          username: "root",
          privateKey,
          hostVerifier: (key: Buffer) => {
            if (accepted.has(Buffer.from(key).toString("base64"))) return true;
            mismatch = true;
            log("guest_host_key_mismatch", { target, alias: hostKeys.alias });
            return false;
          },
        });
    });
  } catch (err) {
    try {
      client.end();
    } catch {
      dial.close();
    }
    dial.close();
    throw err;
  }
  return { client, dial };
}

function endConnection(conn: { client: Client; dial: IrohDial } | null): void {
  if (!conn) return;
  try {
    conn.client.end();
  } catch {
    conn.dial.close();
  }
  conn.dial.close();
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const timer = setTimeout(done, ms);
    function done() {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    }
    signal?.addEventListener("abort", done, { once: true });
  });
}

export async function runGuestSession(
  privateKeyPath: string,
  target: string,
  program: string,
  io: CommandIo,
  dumbpipePath: string,
  log: GatewayLog,
  signal?: AbortSignal,
  hostKeys?: GuestHostKeys,
): Promise<number> {
  if (!dumbpipeConnectArgv(target)) {
    const err = new NonIrohGuestAddressError(target);
    log("guest_session_refused", { target, error: err.message });
    await io.writeErr(new TextEncoder().encode(`guest session failed: ${err.message}\n`));
    return 1;
  }
  if (!hostKeys || hostKeys.keys.length === 0) {
    const err = new MissingGuestHostKeysError(target);
    log("guest_session_refused", { target, error: err.message });
    await io.writeErr(new TextEncoder().encode(`guest session failed: ${err.message}\n`));
    return 1;
  }
  if (signal?.aborted) {
    log("guest_session_terminated", { target, phase: "before_connect" });
    return TERMINATED_SESSION_EXIT_CODE;
  }
  const privateKey = await Deno.readTextFile(privateKeyPath);
  let conn: { client: Client; dial: IrohDial } | null = null;
  try {
    conn = await connect(target, dumbpipePath, privateKey, 30_000, log, hostKeys, signal);
    const client = conn.client;
    return await new Promise<number>((resolve) => {
      let settled = false;
      const finish = (code: number) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        resolve(code);
      };
      function onAbort() {
        log("guest_session_terminated", { target, phase: "session" });
        finish(TERMINATED_SESSION_EXIT_CODE);
      }
      signal?.addEventListener("abort", onAbort, { once: true });
      client.on("close", () => finish(TERMINATED_SESSION_EXIT_CODE));
      client.exec(program, { pty: io.pty ?? false }, (err, stream) => {
        if (err) {
          log("guest_exec_failed", { target, error: err.message });
          finish(1);
          return;
        }
        log("guest_session_started", { target });
        io.onData((chunk) => stream.write(Buffer.from(chunk)));
        io.onClose(() => stream.end());
        stream.on("data", (chunk: Uint8Array) => void io.write(chunk));
        stream.stderr.on("data", (chunk: Uint8Array) => void io.writeErr(chunk));
        stream.on("close", (code: number | undefined) => {
          log("guest_session_exit", { target, code: code ?? 0 });
          finish(code ?? 0);
        });
      });
    });
  } catch (err) {
    if (signal?.aborted) {
      log("guest_session_terminated", { target, phase: "connect" });
      return TERMINATED_SESSION_EXIT_CODE;
    }
    log("guest_session_failed", { target, error: String(err) });
    await io.writeErr(new TextEncoder().encode(`guest session failed: ${String(err)}\n`));
    return 1;
  } finally {
    endConnection(conn);
  }
}

export async function pollGuestReady(
  privateKeyPath: string,
  target: string,
  timeoutMs: number,
  dumbpipePath: string,
  log: GatewayLog,
  signal?: AbortSignal,
  hostKeys?: GuestHostKeys,
): Promise<boolean> {
  if (!dumbpipeConnectArgv(target)) {
    log("guest_ssh_refused", { target, error: new NonIrohGuestAddressError(target).message });
    return false;
  }
  if (!hostKeys || hostKeys.keys.length === 0) {
    log("guest_ssh_refused", { target, error: new MissingGuestHostKeysError(target).message });
    return false;
  }
  const privateKey = await Deno.readTextFile(privateKeyPath).catch(() => "");
  if (!privateKey) return false;
  const deadline = Date.now() + timeoutMs;
  let attempt = 0;
  while (Date.now() < deadline && !signal?.aborted) {
    attempt += 1;
    let conn: { client: Client; dial: IrohDial } | null = null;
    try {
      conn = await connect(target, dumbpipePath, privateKey, 10_000, log, hostKeys, signal);
      const client = conn.client;
      const ok = await new Promise<boolean>((resolve) => {
        const onAbort = () => resolve(false);
        signal?.addEventListener("abort", onAbort, { once: true });
        client.exec("true", (err, stream) => {
          if (err) return resolve(false);
          stream.on("close", (code: number | undefined) => {
            signal?.removeEventListener("abort", onAbort);
            resolve(code === 0);
          });
          stream.resume();
        });
      });
      if (ok) {
        log("guest_ssh_ready", { target, attempt });
        return true;
      }
    } catch (err) {
      log("guest_ssh_poll", { target, attempt, error: String(err) });
      if (err instanceof GuestHostKeyMismatchError) return false;
    } finally {
      endConnection(conn);
    }
    await sleep(POLL_INTERVAL_MS, signal);
  }
  if (signal?.aborted) {
    log("guest_ssh_poll_terminated", { target, attempt });
    return false;
  }
  log("guest_ssh_timeout", { target, timeoutMs });
  return false;
}

export interface IrohSessionProviderOptions {
  io: CommandIo;
  log: GatewayLog;
  dumbpipePath: string;
  generateKeypair?: SshSessionProvider["generateKeypair"];
}

export function createIrohSessionProvider(opts: IrohSessionProviderOptions): SshSessionProvider {
  return {
    generateKeypair: (vmName) => {
      if (!opts.generateKeypair) throw new Error("no keypair generator configured");
      return opts.generateKeypair(vmName);
    },
    pollReady: (privateKeyPath, target, timeoutMs, signal, hostKeys) =>
      pollGuestReady(privateKeyPath, target, timeoutMs, opts.dumbpipePath, opts.log, signal, hostKeys),
    runSession: (privateKeyPath, target, program, signal, hostKeys) =>
      runGuestSession(privateKeyPath, target, program, opts.io, opts.dumbpipePath, opts.log, signal, hostKeys),
  };
}
