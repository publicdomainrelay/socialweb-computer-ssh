// @ts-types="npm:@types/ssh2@^1"
import { Buffer } from "node:buffer";
import { Duplex } from "node:stream";
import { Client } from "ssh2";
import { tunnelWsUrl } from "@publicdomainrelay/requester-xrpc";
import type { CommandIo } from "@publicdomainrelay/socialweb-computer-abc";

/**
 * The guest's tunnel as a duplex stream.
 *
 * The tunnel is a WebSocket that carries raw bytes to the guest's sshd; that is
 * all `websocat --binary` did. Doing it here removes the ssh binary, websocat,
 * the ProxyCommand string, and ensureWebsocat -- which mutates the process PATH,
 * a bug in a server running concurrent work.
 */
async function tunnelStream(url: string): Promise<Duplex> {
  const ws = new WebSocket(url);
  ws.binaryType = "arraybuffer";
  // ssh2 writes the client banner immediately on connect, so the socket has to
  // be OPEN before it is handed over -- otherwise the first writes throw
  // InvalidStateError and the handshake never starts.
  await new Promise<void>((resolve, reject) => {
    ws.addEventListener("open", () => resolve(), { once: true });
    ws.addEventListener("error", () => reject(new Error(`tunnel websocket to ${url} failed`)), { once: true });
  });
  const stream = new Duplex({
    read() { /* push happens from the socket */ },
    write(chunk: Uint8Array, _encoding, cb) {
      try {
        ws.send(chunk);
        cb();
      } catch (err) {
        cb(err as Error);
      }
    },
    final(cb) {
      try {
        ws.close();
      } catch { /* already closed */ }
      cb();
    },
  });
  ws.addEventListener("message", (event) => stream.push(new Uint8Array(event.data as ArrayBuffer)));
  ws.addEventListener("close", () => stream.push(null));
  ws.addEventListener("error", () => stream.destroy(new Error("tunnel websocket failed")));
  return stream;
}

async function connect(fqdn: string, privateKey: string, timeoutMs: number): Promise<Client> {
  const sock = await tunnelStream(tunnelWsUrl(fqdn));
  const client = new Client();
  await new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("tunnel connect timed out")), timeoutMs);
    client
      .on("ready", () => {
        clearTimeout(timer);
        resolve();
      })
      .on("error", (err: Error) => {
        clearTimeout(timer);
        reject(err);
      })
      .connect({
        sock,
        username: "root",
        privateKey,
        // The trust anchor is the tunnel registration, not the guest's host key.
        hostVerifier: () => true,
      });
  });
  return client;
}

/**
 * Run one command on the guest, with the SSH channel as its terminal.
 *
 * Never rejects. runComputeContract has no try/catch around the SSH step, so a
 * rejection would skip the rest of the flow -- including vm.delete, which would
 * leak the VM.
 */
export async function runSessionOverTunnel(
  privateKeyPath: string,
  fqdn: string,
  program: string,
  io: CommandIo,
  log: (event: string, data?: Record<string, unknown>) => void,
): Promise<number> {
  const privateKey = await Deno.readTextFile(privateKeyPath);
  let client: Client | null = null;
  try {
    client = await connect(fqdn, privateKey, 30_000);
    return await new Promise<number>((resolve) => {
      // A pty on the guest too, when the client allocated one: without it the
      // command runs with piped stdio and programs that check isatty behave as
      // though they were never given a terminal.
      client!.exec(program, { pty: io.pty ?? false }, (err, stream) => {
        if (err) {
          log("guest_exec_failed", { fqdn, error: err.message });
          resolve(1);
          return;
        }
        io.onData((chunk) => stream.write(Buffer.from(chunk)));
        io.onClose(() => stream.end());
        stream.on("data", (chunk: Uint8Array) => void io.write(chunk));
        stream.stderr.on("data", (chunk: Uint8Array) => void io.writeErr(chunk));
        stream.on("close", (code: number | undefined) => {
          log("guest_session_exit", { fqdn, code: code ?? 0 });
          resolve(code ?? 0);
        });
      });
    });
  } catch (err) {
    log("guest_session_failed", { fqdn, error: String(err) });
    await io.writeErr(new TextEncoder().encode(`guest session failed: ${String(err)}\n`));
    return 1;
  } finally {
    try {
      client?.end();
    } catch { /* already gone */ }
  }
}

/**
 * Is the guest's sshd reachable yet? The shipped poll spawns `ssh true` every
 * five seconds; this is a connect and a one-shot command.
 */
export async function pollGuestReady(
  privateKeyPath: string,
  fqdn: string,
  timeoutMs: number,
  log: (event: string, data?: Record<string, unknown>) => void,
): Promise<boolean> {
  const privateKey = await Deno.readTextFile(privateKeyPath).catch(() => "");
  if (!privateKey) return false;
  const deadline = Date.now() + timeoutMs;
  let attempt = 0;
  while (Date.now() < deadline) {
    attempt += 1;
    let client: Client | null = null;
    try {
      client = await connect(fqdn, privateKey, 10_000);
      const ok = await new Promise<boolean>((resolve) => {
        client!.exec("true", (err, stream) => {
          if (err) return resolve(false);
          stream.on("close", (code: number | undefined) => resolve(code === 0));
          stream.resume();
        });
      });
      if (ok) {
        log("guest_ssh_ready", { fqdn, attempt });
        return true;
      }
    } catch (err) {
      log("guest_ssh_poll", { fqdn, attempt, error: String(err) });
    } finally {
      try {
        client?.end();
      } catch { /* already gone */ }
    }
    await new Promise((r) => setTimeout(r, 5_000));
  }
  log("guest_ssh_timeout", { fqdn, timeoutMs });
  return false;
}
