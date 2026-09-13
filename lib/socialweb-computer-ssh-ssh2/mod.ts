// @ts-types="npm:@types/ssh2@^1"
import { Buffer } from "node:buffer";
import { Server, utils, type Connection, type Session } from "ssh2";
import type { CommandIo, SshServerHandle, SshServerOptions } from "@publicdomainrelay/socialweb-computer-abc";
import type { AuthorizedAccount, PresentedKey } from "@publicdomainrelay/socialweb-computer-common";

interface PublicKeyContext {
  method: string;
  username: string;
  key?: { algo: string; data: Uint8Array };
  signature?: Uint8Array;
  blob?: Uint8Array;
  hashAlgo?: string;
  accept(): void;
  reject(methods?: string[]): void;
}

interface ChannelLike {
  write(chunk: Uint8Array): boolean;
  stderr: { write(chunk: Uint8Array): boolean };
  exit(code: number): void;
  close(): void;
  on(event: string, handler: (...args: never[]) => void): void;
  end(): void;
}

type AcceptFn = (() => unknown) | undefined;
type RejectFn = (() => void) | undefined;

function parseableHostKey(pem: string): boolean {
  if (!pem.includes("PRIVATE KEY")) return false;
  const parsed = utils.parseKey(pem);
  return !(parsed instanceof Error);
}

async function loadOrCreateHostKey(path: string, log: SshServerOptions["log"]): Promise<string> {
  const existing = await Deno.readTextFile(path).catch(() => "");
  if (parseableHostKey(existing)) return existing;
  if (existing) log("host_key_unreadable_regenerating", { path, bytes: existing.length });
  const generated = utils.generateKeyPairSync("ed25519").private;
  const dir = path.split("/").slice(0, -1).join("/");
  if (dir) await Deno.mkdir(dir, { recursive: true });
  await Deno.writeTextFile(path, generated, { mode: 0o600 });
  log("host_key_generated", { path });
  return generated;
}

/**
 * ssh2 hands the presented signature to the application and never verifies it
 * itself, so a client that knows a registered public key could authenticate
 * without the private half. Public keys here are public by construction -- they
 * are read from an unauthenticated PDS record -- so the signature is the only
 * thing that proves possession.
 *
 * A publickey request without a signature is a probe: ssh2 answers it with
 * PK_OK and the client follows up with the signed request, which is verified.
 */
export function verifyPublicKeySignature(
  key: PresentedKey,
  ctx: { signature?: Uint8Array; blob?: Uint8Array; hashAlgo?: string },
): boolean {
  if (!ctx.signature) return true;
  if (!ctx.blob) return false;
  const parsed = utils.parseKey(`${key.algo} ${key.key}`);
  if (parsed instanceof Error) return false;
  try {
    return parsed.verify(Buffer.from(ctx.blob), Buffer.from(ctx.signature), ctx.hashAlgo) === true;
  } catch {
    return false;
  }
}

export function createSshServer(opts: SshServerOptions): SshServerHandle {
  const { config, authorizer, runner, defaultCommand, log } = opts;
  let server: Server | null = null;

  function handleConnection(connection: Connection): void {
    let account: AuthorizedAccount | null = null;

    connection.on("authentication", (ctx: PublicKeyContext) => {
      if (ctx.method !== "publickey" || !ctx.key) return ctx.reject(["publickey"]);
      const presented = { algo: ctx.key.algo, key: btoa(String.fromCharCode(...ctx.key.data)) };
      if (!verifyPublicKeySignature(presented, ctx)) {
        log("auth_bad_signature", { username: ctx.username, algo: presented.algo });
        return ctx.reject(["publickey"]);
      }
      authorizer.authorize(ctx.username, presented)
        .then((resolved) => {
          if (!resolved) {
            log("auth_rejected", { username: ctx.username });
            return ctx.reject(["publickey"]);
          }
          account = resolved;
          log("auth_accepted", { username: ctx.username, did: resolved.did });
          ctx.accept();
        })
        .catch((err) => {
          log("auth_error", { username: ctx.username, error: String(err) });
          ctx.reject(["publickey"]);
        });
    });

    connection.on("ready", () => {
      connection.on("session", (acceptSession: () => Session) => {
        const session = acceptSession();
        const env: Record<string, string> = {};
        let channel: ChannelLike | null = null;

        const ensureChannel = (accept: AcceptFn, reject: RejectFn): ChannelLike | null => {
          if (channel) return channel;
          if (typeof accept !== "function") return null;
          channel = accept() as ChannelLike | null;
          if (!channel) {
            reject?.();
            return null;
          }
          channel.on("error", ((err: Error) => log("channel_error", { error: String(err) })) as never);
          return channel;
        };

        const start = (ch: ChannelLike, command: string): void => {
          if (!account) {
            ch.stderr.write(new TextEncoder().encode("authentication required\n"));
            ch.exit(1);
            ch.end();
            return;
          }
          void runOnChannel(ch, account, command, env);
        };

        session.on("env", (accept: AcceptFn, _reject: RejectFn, info: { key: string; val: string }) => {
          env[info.key] = info.val;
          ensureChannel(accept, undefined);
        });

        session.on("exec", (accept: AcceptFn, reject: RejectFn, info: { command: string }) => {
          if (channel) return reject?.();
          const ch = ensureChannel(accept, reject);
          if (ch) start(ch, info.command);
        });

        session.on("shell", (accept: AcceptFn, reject: RejectFn) => {
          if (channel) return reject?.();
          const ch = ensureChannel(accept, reject);
          if (ch) start(ch, defaultCommand);
        });
      });
    });

    connection.on("error", (err: Error) => log("connection_error", { error: String(err) }));
  }

  async function runOnChannel(
    channel: ChannelLike,
    account: AuthorizedAccount,
    command: string,
    env: Record<string, string>,
  ): Promise<void> {
    let closed = false;
    let exited = false;
    const encoder = new TextEncoder();
    const safeWrite = (write: (chunk: Uint8Array) => boolean, chunk: Uint8Array): void => {
      if (closed) return;
      try {
        write(chunk);
      } catch {
        closed = true;
      }
    };

    const io: CommandIo = {
      write: (chunk) => safeWrite((c) => channel.write(c), chunk),
      writeErr: (chunk) => safeWrite((c) => channel.stderr.write(c), chunk),
      onData: (handler) => { channel.on("data", handler as (...args: never[]) => void); },
      onClose: (handler) => {
        channel.on("close", (() => { closed = true; handler(); }) as (...args: never[]) => void);
        channel.on("end", handler as (...args: never[]) => void);
        channel.on("error", (() => { closed = true; }) as (...args: never[]) => void);
      },
      exit: (code) => {
        exited = true;
        if (closed) return;
        try {
          channel.exit(code);
          channel.end();
        } catch {
          // channel already gone
        }
      },
    };

    try {
      await runner.run(account, command, env, io);
    } catch (err) {
      if (exited) {
        log("post_exit_error", { did: account.did, error: String(err) });
        return;
      }
      log("provisioning_failed", { did: account.did, error: String(err) });
      safeWrite((c) => channel.stderr.write(c), encoder.encode(`provisioning failed: ${String(err)}\n`));
      io.exit(1);
    }
  }

  return {
    async listen(): Promise<number> {
      const hostKey = await loadOrCreateHostKey(config.hostKeyPath, log);
      return await new Promise<number>((resolve, reject) => {
        server = new Server({ hostKeys: [hostKey], banner: config.banner }, (connection: Connection) => {
          handleConnection(connection);
        });
        server.on("error", reject);
        server.listen(config.port, config.hostname, () => {
          const address = (server as unknown as { address(): { port: number } }).address();
          log("ssh_listening", { hostname: config.hostname, port: address.port });
          resolve(address.port);
        });
      });
    },
    async shutdown(): Promise<void> {
      await new Promise<void>((resolve) => {
        if (!server) return resolve();
        server.close(() => resolve());
      });
      server = null;
    },
  };
}
