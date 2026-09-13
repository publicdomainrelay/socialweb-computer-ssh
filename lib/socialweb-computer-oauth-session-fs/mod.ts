import type { SessionStore } from "@atproto/oauth-client";
import type { OAuthSessionSource } from "@publicdomainrelay/socialweb-computer-abc";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export interface FileSessionStore {
  store: SessionStore;
  snapshot(did: string): Promise<Record<string, unknown>>;
  merge(did: string, value: Record<string, unknown>): Promise<void>;
  list(): Promise<string[]>;
}

export function createFileSessionStore(filePath: string): FileSessionStore {
  let queue: Promise<unknown> = Promise.resolve();

  function serialize<T>(fn: () => Promise<T>): Promise<T> {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  async function read(): Promise<Record<string, unknown>> {
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
    return parsed as Record<string, unknown>;
  }

  async function write(data: Record<string, unknown>): Promise<void> {
    const dir = filePath.split("/").slice(0, -1).join("/");
    if (dir) await Deno.mkdir(dir, { recursive: true, mode: DIR_MODE });
    const tmp = `${filePath}.${crypto.randomUUID()}.tmp`;
    await Deno.writeTextFile(tmp, JSON.stringify(data, null, 2), { mode: FILE_MODE });
    await Deno.rename(tmp, filePath);
    await Deno.chmod(filePath, FILE_MODE).catch(() => {});
  }

  const store: SessionStore = {
    get: (sub) => serialize(async () => (await read())[sub] as never),
    set: (sub, value) => serialize(async () => {
      const data = await read();
      data[sub] = value;
      await write(data);
    }),
    del: (sub) => serialize(async () => {
      const data = await read();
      delete data[sub];
      await write(data);
    }),
  };

  return {
    store,
    snapshot: (did) => serialize(async () => {
      const data = await read();
      return data[did] === undefined ? {} : { [did]: data[did] };
    }),
    merge: (did, value) => serialize(async () => {
      const data = await read();
      if (value[did] === undefined) delete data[did];
      else data[did] = value[did];
      await write(data);
    }),
    list: () => serialize(async () => Object.keys(await read())),
  };
}

export interface OAuthSessionSourceOptions {
  sessionStore: FileSessionStore;
  tempDirPrefix?: string;
}

export function createFsOAuthSessionSource(opts: OAuthSessionSourceOptions): OAuthSessionSource {
  const prefix = opts.tempDirPrefix ?? "socialweb-computer-ssh-";
  const locks = new Map<string, Promise<unknown>>();

  /**
   * The requester rotates the refresh token, so two connections for one account
   * must not both read the same token: the second would be handed a token the
   * first already consumed. Different accounts still run concurrently.
   */
  function withAccountLock<T>(did: string, fn: () => Promise<T>): Promise<T> {
    const prior = locks.get(did) ?? Promise.resolve();
    const run = prior.then(fn, fn);
    const chained = run.catch(() => {});
    locks.set(did, chained);
    void chained.then(() => {
      if (locks.get(did) === chained) locks.delete(did);
    });
    return run;
  }

  return {
    async withSessionFor<T>(did: string, fn: (lease: { sessionPath: string }) => Promise<T>): Promise<T> {
      return await withAccountLock(did, async () => {
        const dir = await Deno.makeTempDir({ prefix });
        await Deno.chmod(dir, DIR_MODE).catch(() => {});
        const sessionPath = `${dir}/session.json`;
        try {
          const snapshot = await opts.sessionStore.snapshot(did);
          if (Object.keys(snapshot).length === 0) {
            throw new Error(`no oauth session stored for ${did}`);
          }
          await Deno.writeTextFile(sessionPath, JSON.stringify(snapshot, null, 2), { mode: FILE_MODE });

          let result: T | undefined;
          let failure: unknown;
          try {
            result = await fn({ sessionPath });
          } catch (err) {
            failure = err;
          }

          try {
            await opts.sessionStore.merge(did, JSON.parse(await Deno.readTextFile(sessionPath)));
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
