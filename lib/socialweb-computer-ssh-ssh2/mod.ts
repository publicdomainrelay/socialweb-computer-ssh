// @ts-types="npm:@types/ssh2@^1"
import { Buffer } from "node:buffer";
import { Server, utils, type Connection, type Session } from "ssh2";
import type { CommandIo, PtySize, SshServerHandle, SshServerOptions } from "@publicdomainrelay/socialweb-computer-abc";
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
  maxConnections: 10_000,
  maxSessions: 1_000,
  sessionsPerAccount: 1000,
  maxAuthAttempts: 6,
  // Long enough to read a banner and accept an unknown host key. At 30s a first
  // connection that paused at the fingerprint prompt was closed underneath the
  // client, which then reported it as "padding error ... message authentication
  // code incorrect" -- a protocol-corruption message for what was only a slow
  // human. The attempt cap, not the clock, is what bounds guessing.
  authTimeoutMs: 120_000,
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

const encoder = new TextEncoder();

/**
 * How long any one step of shutdown may take.
 *
 * A restart has to make progress: the listening socket is closed first, so a
 * shutdown that waits indefinitely leaves the door down rather than merely slow
 * to come back.
 */
const SHUTDOWN_GRACE_MS = 5_000;

/** Resolve after `work`, or after `ms` -- whichever is first. Never rejects. */
function settleWithin(work: Promise<unknown>, ms: number): Promise<void> {
  const bounded = Promise.resolve(work).catch(() => {}).then(() => {});
  const deadline = new Promise<void>((resolve) => setTimeout(resolve, ms));
  return Promise.race([bounded, deadline]);
}

/**
 * Make a message safe to write to a client's terminal.
 *
 * A pty puts the client's terminal in raw mode, so nothing downstream turns a
 * bare newline into CRLF and anything this server writes arrives as a staircase:
 *
 *     line one
 *              line two
 *
 * Guest output does not need this -- its own tty already applied ONLCR -- which
 * is why the pattern is `\r?\n` and not `\n`: a plain substitution would turn
 * guest CRLF into CRCRLF. Non-pty sessions get the bytes untouched, because
 * piped stdio wants them verbatim.
 */
function forClientTerminal(pty: PtySize | undefined, chunk: Uint8Array): Uint8Array {
  if (!pty) return chunk;
  const text = new TextDecoder().decode(chunk);
  if (!text.includes("\n")) return chunk;
  return encoder.encode(text.replace(/\r?\n/g, "\r\n"));
}

/**
 * What a client is told when no key it holds could authenticate.
 *
 * Only when the deployment has not supplied `noKeyCouldMatchMessage`: the server
 * cannot know the site's name or where keys are registered.
 */
function defaultNoKeyMessage(username: string): string {
  return [
    "",
    "socialweb-computer-ssh",
    "",
    `  No SSH key registered for "${username}" can sign in here.`,
    "",
    "  If that is your handle, register an SSH key against the account first.",
    "  If it is not, use your handle as the username -- the account, not just the",
    "  key, is what this door authenticates against.",
    "",
  ].join("\n");
}

export function createSshServer(opts: SshServerOptions): SshServerHandle {
  const { config, authorizer, runner, defaultCommand, log } = opts;
  const limits = { ...DEFAULTS, ...config };
  let server: Server | null = null;
  /**
   * Connections still open, so shutdown can end them.
   *
   * Tracked because net.Server.close() waits for every connection to end before
   * it calls back; without this, a single idle session blocks a restart.
   */
  const openConnections = new Set<Connection>();
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
    /**
     * The username of a connection accepted only in order to explain.
     *
     * Set when the authorizer says the username names no account at all, which is
     * the one case where accepting is safe. A client offers its keys in order and
     * stops at the first the server accepts, so accepting an unassociated key
     * would pre-empt the key that would have worked -- but if the username cannot
     * name an account, no key would have worked, and refusing only leaves the
     * caller with "Permission denied (publickey)" and no idea why.
     */
    let noKeyCouldMatchUsername: string | null = null;
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
            // Rejected, deliberately, and this is the load-bearing part of the
            // design: a client offers its keys in order and stops at the first
            // one the server accepts. A typical ~/.ssh holds several, and the
            // associated one is rarely first -- id_ecdsa often precedes
            // id_ed25519. Accepting an unassociated key to explain on would end
            // authentication there, and the key that would have worked is never
            // tried. Refusing is what lets ssh fall through to it.
            //
            // The cost is that this refusal is mute: USERAUTH_FAILURE carries no
            // text. Explaining an unassociated key needs keyboard-interactive's
            // INFO_REQUEST, which the client only reaches once publickey is
            // exhausted.
            log("auth_rejected", { username: ctx.username });
            return ctx.reject(["publickey"]);
          }
          account = resolved;
          log("auth_accepted", { username: ctx.username, did: resolved.did });
          ctx.accept();
        })
        .catch((err: { kind?: string }) => {
          if (err?.kind === "no_key_could_match") {
            noKeyCouldMatchUsername = ctx.username;
            log("auth_accepted_no_key_could_match", { username: ctx.username });
            return ctx.accept();
          }
          // Everything else stays a rejection. A lookup failure says nothing
          // about the key, and a key that is simply not in the list must be
          // refused so the client offers its remaining ones.
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
        // A pty the client asked for. Accepted rather than refused: the guest
        // session allocates its own pty so the command actually gets a terminal,
        // and refusing only makes OpenSSH print "PTY allocation request failed"
        // while the run proceeds anyway.
        let pty: PtySize | undefined;

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
            const explanation = noKeyCouldMatchUsername === null
              ? "authentication required\n"
              : (config.noKeyCouldMatchMessage ?? defaultNoKeyMessage(noKeyCouldMatchUsername));
            log("session_refused_no_key_could_match", { username: noKeyCouldMatchUsername });
            void ch.stderr.write(forClientTerminal(pty, encoder.encode(explanation)));
            ch.exit(1);
            ch.end();
            return;
          }
          const refusal = acquire(account);
          if (refusal) {
            log("session_refused", { did: account.did, reason: refusal });
            void ch.stderr.write(forClientTerminal(pty, encoder.encode(`${refusal}\n`)));
            ch.exit(1);
            ch.end();
            return;
          }
          void runOnChannel(ch, account, command, env, pty).finally(() => release(account!));
        };

        session.on("pty", (accept: AcceptFn, _reject: RejectFn, info: { cols?: number; rows?: number }) => {
          pty = { cols: info.cols ?? 80, rows: info.rows ?? 24 };
          accept?.();
        });

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
    pty?: PtySize,
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

    // A pty puts the client's terminal in raw mode, so nothing downstream will
    // turn a bare newline into CRLF. Guest output does not need this -- its own
    // tty already applied ONLCR -- but anything this server writes has never
    // been near a tty, and arrives as a staircase:
    //     line one
    //              line two
    // `\r?\n` rather than `\n` so already-CRLF guest output is left alone.
    const io: CommandIo = {
      pty,
      write: (chunk) => writeTo((c) => channel.write(c), forClientTerminal(pty, chunk)),
      writeErr: (chunk) => writeTo((c) => channel.stderr.write(c), forClientTerminal(pty, chunk)),
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
      await io.writeErr(encoder.encode(`provisioning failed: ${String(err)}\n`));
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
          openConnections.add(connection);
          connection.on("close", () => openConnections.delete(connection));
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
      await settleWithin(Promise.resolve(runnerWithShutdown.shutdown?.()), SHUTDOWN_GRACE_MS);

      const stoppedAccepting = new Promise<void>((resolve) => {
        if (!server) return resolve();
        server.close(() => resolve());
      });

      // net.Server.close() stops accepting new connections but resolves only
      // once every existing one has ended. A client sitting at a guest prompt
      // never ends on its own, so the unit would stay in stop-sigterm with the
      // listening socket already closed: the door is down and cannot be
      // restarted without killing the process by hand. Ending the sessions is
      // what makes the close() above able to finish.
      for (const open of openConnections) {
        try {
          open.end();
        } catch { /* already gone */ }
      }
      await settleWithin(stoppedAccepting, SHUTDOWN_GRACE_MS);

      // Last resort for a connection that ignored the polite close. Bounded
      // shutdown matters more here than a tidy one: a restart that wedges is
      // worse than a session that gets cut.
      for (const open of openConnections) {
        try {
          (open as unknown as { destroy?: () => void }).destroy?.();
        } catch { /* already gone */ }
      }
      server = null;
    },
  };
}
