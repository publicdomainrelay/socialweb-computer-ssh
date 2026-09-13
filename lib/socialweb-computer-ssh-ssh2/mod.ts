// @ts-types="npm:@types/ssh2@^1"
import { Server, utils, type Connection, type Session } from "ssh2";
import type { CommandIo, SshServerHandle, SshServerOptions } from "@publicdomainrelay/socialweb-computer-abc";
import type { AuthorizedAccount } from "@publicdomainrelay/socialweb-computer-common";

interface PublicKeyContext {
  method: string;
  username: string;
  key?: { algo: string; data: Uint8Array };
  accept(): void;
  reject(methods?: string[]): void;
}

interface ChannelLike {
  write(chunk: Uint8Array): boolean;
  stderr: { write(chunk: Uint8Array): boolean };
  exit(code: number): void;
  on(event: string, handler: (...args: never[]) => void): void;
  end(): void;
}

type AcceptFn = (() => unknown) | undefined;

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

export function createSshServer(opts: SshServerOptions): SshServerHandle {
  const { config, authorizer, runner, defaultCommand, log } = opts;
  let server: Server | null = null;

  function handleConnection(connection: Connection): void {
    let account: AuthorizedAccount | null = null;

    connection.on("authentication", (ctx: PublicKeyContext) => {
      if (ctx.method !== "publickey" || !ctx.key) return ctx.reject(["publickey"]);
      const presented = { algo: ctx.key.algo, key: btoa(String.fromCharCode(...ctx.key.data)) };
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

        const ensureChannel = (accept: AcceptFn): ChannelLike | null => {
          if (channel) return channel;
          if (typeof accept !== "function") return null;
          channel = accept() as ChannelLike | null;
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

        session.on("env", (accept: AcceptFn, _reject: unknown, info: { key: string; val: string }) => {
          env[info.key] = info.val;
          ensureChannel(accept);
        });

        session.on("exec", (accept: AcceptFn, _reject: unknown, info: { command: string }) => {
          const ch = ensureChannel(accept);
          if (ch) start(ch, info.command);
        });

        session.on("shell", (accept: AcceptFn) => {
          const ch = ensureChannel(accept);
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
    let exited = false;
    const io: CommandIo = {
      write: (chunk) => { channel.write(chunk); },
      writeErr: (chunk) => { channel.stderr.write(chunk); },
      onData: (handler) => { channel.on("data", handler as (...args: never[]) => void); },
      onClose: (handler) => {
        channel.on("close", handler as (...args: never[]) => void);
        channel.on("end", handler as (...args: never[]) => void);
      },
      exit: (code) => {
        exited = true;
        channel.exit(code);
        channel.end();
      },
    };
    try {
      await runner.run(account, command, env, io);
    } catch (err) {
      if (!exited) {
        channel.stderr.write(new TextEncoder().encode(`provisioning failed: ${String(err)}\n`));
        io.exit(1);
      } else {
        log("post_exit_error", { did: account.did, error: String(err) });
      }
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
