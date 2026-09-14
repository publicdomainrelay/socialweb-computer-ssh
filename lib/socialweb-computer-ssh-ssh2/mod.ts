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
  on(event: string, handler: (...args: never[]) => void): void;
  once(event: string, handler: (...args: never[]) => void): void;
  end(): void;
}

type AcceptFn = (() => unknown) | undefined;
type RejectFn = (() => void) | undefined;

const DEFAULTS = {
  maxConnections: 200,
  maxSessions: 8,
  sessionsPerAccount: 2,
  maxAuthAttempts: 6,
  authTimeoutMs: 30_000,
};

// rsa-sha2 is the SHA-2 RSA form; bare ssh-rsa and ssh-dss are SHA-1 and are not
// accepted. A key is self-registered, so this is hygiene rather than escalation.
const ALLOWED_KEY_ALGOS = new Set([
  "ssh-ed25519",
  "ecdsa-sha2-nistp256",
  "ecdsa-sha2-nistp384",
  "ecdsa-sha2-nistp521",
  "sk-ssh-ed25519@openssh.com",
  "sk-ecdsa-sha2-nistp256@openssh.com",
  "rsa-sha2-256",
  "rsa-sha2-512",
]);

function parseableHostKey(pem: string): boolean {
  if (!pem.includes("PRIVATE KEY")) return false;
  const parsed = utils.parseKey(pem);
  return !(parsed instanceof Error);
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
 * The caller must not do any work for a probe -- see handleConnection.
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

async function loadOrCreateHostKey(path: string, log: SshServerOptions["log"]): Promise<string> {
  const existing = await Deno.readTextFile(path).catch(() => null);
  if (existing !== null) {
    // An unreadable host key is an identity change, not something to paper over:
    // starting up with a fresh key would quietly change who this server is.
    if (!parseableHostKey(existing)) {
      throw new Error(`${path} exists but is not a usable private key; refusing to start with a different identity`);
    }
    const stat = await Deno.stat(path);
    if ((stat.mode ?? 0) & 0o077) {
      await Deno.chmod(path, 0o600);
      log("host_key_permissions_repaired", { path });
    }
    return existing;
  }
  const generated = utils.generateKeyPairSync("ed25519").private;
  const dir = path.split("/").slice(0, -1).join("/");
  if (dir) await Deno.mkdir(dir, { recursive: true, mode: 0o700 });
  const file = await Deno.open(path, { createNew: true, write: true, mode: 0o600 });
  try {
    await file.write(new TextEncoder().encode(generated));
  } finally {
    file.close();
  }
  log("host_key_generated", { path });
  return generated;
}

export function createSshServer(opts: SshServerOptions): SshServerHandle {
  const { config, authorizer, runner, defaultCommand, log } = opts;
  const limits = { ...DEFAULTS, ...config };
  let server: Server | null = null;
  let running = 0;
  const perAccount = new Map<string, number>();

  function acquire(account: AuthorizedAccount): string | null {
    const held = perAccount.get(account.did) ?? 0;
    if (running >= limits.maxSessions) return `server is at its ${limits.maxSessions} concurrent session limit`;
    if (held >= limits.sessionsPerAccount) {
      return `account already has ${held} sessions running`;
    }
    running += 1;
    perAccount.set(account.did, held + 1);
    return null;
  }

  function release(account: AuthorizedAccount): void {
    running = Math.max(0, running - 1);
    const held = (perAccount.get(account.did) ?? 1) - 1;
    if (held <= 0) perAccount.delete(account.did);
    else perAccount.set(account.did, held);
  }

  function handleConnection(connection: Connection): void {
    let account: AuthorizedAccount | null = null;
    let attempts = 0;

    // Nothing before authentication should be able to hold a connection open.
    const authTimer = setTimeout(() => {
      log("auth_timeout", {});
      connection.end();
    }, limits.authTimeoutMs);

    connection.on("authentication", (ctx: PublicKeyContext) => {
      if (ctx.method !== "publickey" || !ctx.key) return ctx.reject(["publickey"]);

      // A probe carries no signature and proves nothing. Answer it without
      // touching the network: otherwise an unauthenticated caller picks a
      // username and a key and makes this host resolve, fetch a DID document,
      // and read a stranger's PDS on their behalf.
      if (!ctx.signature) return ctx.accept();

      attempts += 1;
      if (attempts > limits.maxAuthAttempts) {
        log("auth_attempts_exceeded", { username: ctx.username });
        return connection.end();
      }

      const presented = { algo: ctx.key.algo, key: Buffer.from(ctx.key.data).toString("base64") };
      if (!ALLOWED_KEY_ALGOS.has(presented.algo)) {
        log("auth_rejected_algo", { username: ctx.username, algo: presented.algo });
        return ctx.reject(["publickey"]);
      }
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
      clearTimeout(authTimer);
      connection.on("session", (acceptSession: () => Session) => {
        const session = acceptSession();
        const env: Record<string, string> = {};
        let envBytes = 0;
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
          const refusal = acquire(account);
          if (refusal) {
            log("session_refused", { did: account.did, reason: refusal });
            ch.stderr.write(new TextEncoder().encode(`${refusal}\n`));
            ch.exit(1);
            ch.end();
            return;
          }
          void runOnChannel(ch, account, command, env).finally(() => release(account!));
        };

        session.on("env", (accept: AcceptFn, _reject: RejectFn, info: { key: string; val: string }) => {
          // Bounded so a client cannot grow this session's memory with env
          // requests alone.
          if (Object.keys(env).length < 64 && envBytes < 8192) {
            env[info.key] = info.val;
            envBytes += info.key.length + info.val.length;
          }
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

    connection.on("error", (err: Error) => {
      clearTimeout(authTimer);
      log("connection_error", { error: String(err) });
    });
    connection.on("close", () => clearTimeout(authTimer));
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

    // Waiting for drain is what keeps a client that stops reading from turning
    // its own backlog into this process's heap.
    const writeTo = (write: (chunk: Uint8Array) => boolean, chunk: Uint8Array): Promise<void> => {
      if (closed) return Promise.resolve();
      return new Promise<void>((resolve) => {
        let ok = false;
        try {
          ok = write(chunk);
        } catch {
          closed = true;
          return resolve();
        }
        if (ok) return resolve();
        channel.once("drain", () => resolve());
      });
    };

    const io: CommandIo = {
      write: (chunk) => writeTo((c) => channel.write(c), chunk),
      writeErr: (chunk) => writeTo((c) => channel.stderr.write(c), chunk),
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
      await writeTo((c) => channel.stderr.write(c), encoder.encode(`provisioning failed: ${String(err)}\n`));
      io.exit(1);
    }
  }

  return {
    async listen(): Promise<number> {
      const hostKey = await loadOrCreateHostKey(config.hostKeyPath, log);
      return await new Promise<number>((resolve, reject) => {
        server = new Server({
          hostKeys: [hostKey],
          banner: config.banner,
          maxConnections: limits.maxConnections,
        } as never, (connection: Connection) => {
          handleConnection(connection);
        });
        server.on("error", reject);
        server.listen(config.port, config.hostname, () => {
          const address = (server as unknown as { address(): { port: number } }).address();
          log("ssh_listening", { hostname: config.hostname, port: address.port, maxConnections: limits.maxConnections });
          resolve(address.port);
        });
      });
    },
    async shutdown(): Promise<void> {
      const runnerWithShutdown = runner as unknown as { shutdown?: () => Promise<void> };
      await runnerWithShutdown.shutdown?.();
      await new Promise<void>((resolve) => {
        if (!server) return resolve();
        server.close(() => resolve());
      });
      server = null;
    },
  };
}
