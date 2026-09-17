import type { SessionStore } from "@publicdomainrelay/socialweb-computer-abc";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

export interface FileSessionStoreOptions {
  onCorrupt?: (info: { path: string; quarantine: string }) => void;
}

export function createFileSessionStore(filePath: string, opts: FileSessionStoreOptions = {}): SessionStore {
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
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // A truncated store must not read as empty without a trace: the next write
      // would persist only its own key and drop every other account. Move the
      // bytes aside so they can be recovered, say so loudly, and carry on rather
      // than wedging every request on a 500.
      const quarantine = `${filePath}.corrupt-${Date.now()}`;
      await Deno.rename(filePath, quarantine);
      opts.onCorrupt?.({ path: filePath, quarantine });
      return {};
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error(`${filePath} is not a JSON object`);
    }
    return parsed as Record<string, OAuthSessionData>;
  }

  async function write(data: Record<string, OAuthSessionData>): Promise<void> {
    const dir = filePath.split("/").slice(0, -1).join("/");
    if (dir) await Deno.mkdir(dir, { recursive: true, mode: DIR_MODE });
    const tmp = `${filePath}.${crypto.randomUUID()}.tmp`;
    const file = await Deno.open(tmp, { create: true, write: true, truncate: true, mode: FILE_MODE });
    try {
      await file.write(new TextEncoder().encode(JSON.stringify(data, null, 2)));
      await file.sync();
    } finally {
      file.close();
    }
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
