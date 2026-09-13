import type { OAuthSessionSource } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export interface SessionStore {
  get(did: string): Promise<OAuthSessionData | undefined>;
  set(did: string, session: OAuthSessionData): Promise<void>;
  del(did: string): Promise<void>;
  list(): Promise<string[]>;
  withAccount<T>(did: string, fn: () => Promise<T>): Promise<T>;
}

export function createFileSessionStore(filePath: string): SessionStore {
  let queue: Promise<unknown> = Promise.resolve();
  const locks = new Map<string, Promise<unknown>>();

  function serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  async function read(): Promise<Record<string, OAuthSessionData>> {
    let raw: string;
    try {
      raw = await Deno.readTextFile(filePath);
    } catch (err) {
      if (err instanceof Deno.errors.NotFound) return {};
      throw err;
    }
    const parsed = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error(`${filePath} is not a JSON object`);
    }
    return parsed as Record<string, OAuthSessionData>;
  }

  async function write(data: Record<string, OAuthSessionData>): Promise<void> {
    const dir = filePath.split("/").slice(0, -1).join("/");
    if (dir) await Deno.mkdir(dir, { recursive: true, mode: DIR_MODE });
    const tmp = `${filePath}.${crypto.randomUUID()}.tmp`;
    await Deno.writeTextFile(tmp, JSON.stringify(data, null, 2), { mode: FILE_MODE });
    await Deno.rename(tmp, filePath);
    await Deno.chmod(filePath, FILE_MODE).catch(() => {});
  }

  return {
    get: (did) => serialize(async () => (await read())[did]),
    set: (did, session) => serialize(async () => {
      const data = await read();
      data[did] = session;
      await write(data);
    }),
    del: (did) => serialize(async () => {
      const data = await read();
      delete data[did];
      await write(data);
    }),
    list: () => serialize(async () => Object.keys(await read())),

    /**
     * The requester rotates the refresh token, so two operations for one account
     * must not both read the same token: the second would be handed a token the
     * first already consumed. Different accounts still run concurrently.
     */
    withAccount<T>(did: string, fn: () => Promise<T>): Promise<T> {
      const prior = locks.get(did) ?? Promise.resolve();
      const run = prior.then(fn, fn);
      const chained = run.catch(() => {});
      locks.set(did, chained);
      void chained.then(() => {
        if (locks.get(did) === chained) locks.delete(did);
      });
      return run;
    },
  };
}

export interface OAuthSessionSourceOptions {
  sessionStore: SessionStore;
  tempDirPrefix?: string;
}

export function createFsOAuthSessionSource(opts: OAuthSessionSourceOptions): OAuthSessionSource {
  const prefix = opts.tempDirPrefix ?? "socialweb-computer-ssh-";

  return {
    async withSessionFor<T>(did: string, fn: (lease: { sessionPath: string }) => Promise<T>): Promise<T> {
      return await opts.sessionStore.withAccount(did, async () => {
        const dir = await Deno.makeTempDir({ prefix });
        await Deno.chmod(dir, DIR_MODE).catch(() => {});
        const sessionPath = `${dir}/session.json`;
        try {
          const stored = await opts.sessionStore.get(did);
          if (!stored) throw new Error(`no oauth session stored for ${did}`);
          await Deno.writeTextFile(sessionPath, JSON.stringify(stored, null, 2), { mode: FILE_MODE });

          let result: T | undefined;
          let failure: unknown;
          try {
            result = await fn({ sessionPath });
          } catch (err) {
            failure = err;
          }

          try {
            await opts.sessionStore.set(did, JSON.parse(await Deno.readTextFile(sessionPath)));
          } catch (err) {
            if (!failure) failure = err;
          }

          if (failure) throw failure;
          return result as T;
        } finally {
          await Deno.remove(dir, { recursive: true }).catch(() => {});
        }
      });
    },
  };
}
