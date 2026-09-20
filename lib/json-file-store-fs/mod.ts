const FILE_MODE = 0o600;
const DIR_MODE = 0o700;

/**
 * A JSON object on disk, addressed by string key.
 *
 * Two properties the callers depend on, neither of which a bare
 * `Deno.writeTextFile` gives:
 *
 * Writes are atomic. The bytes go to a temporary file and are renamed into
 * place, so a reader sees either the previous contents or the next ones and
 * never a half-written file. A process that dies mid-write leaves the previous
 * contents intact.
 *
 * A truncated file is moved aside, not read as empty. Without that, the next
 * write would persist only its own key and drop every other entry -- a whole
 * store of accounts or tokens lost to one bad parse.
 */
export interface JsonFileStore<T> {
  get(key: string): Promise<T | undefined>;
  set(key: string, value: T): Promise<void>;
  del(key: string): Promise<void>;
  list(): Promise<string[]>;
}

export interface JsonFileStoreOptions {
  onCorrupt?: (info: { path: string; quarantine: string }) => void;
}

export function createJsonFileStore<T>(
  filePath: string,
  opts: JsonFileStoreOptions = {},
): JsonFileStore<T> {
  let queue: Promise<unknown> = Promise.resolve();

  /**
   * Read-modify-write against one file cannot interleave. Serializing every
   * operation rather than only the writes is what makes `set` a merge: two
   * concurrent `set`s that both read first would each write back a map holding
   * only their own key.
   */
  function serialize<R>(fn: () => Promise<R>): Promise<R> {
    const run = queue.then(fn, fn);
    queue = run.catch(() => {});
    return run;
  }

  async function read(): Promise<Record<string, T>> {
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
      const quarantine = `${filePath}.corrupt-${Date.now()}`;
      await Deno.rename(filePath, quarantine);
      opts.onCorrupt?.({ path: filePath, quarantine });
      return {};
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      throw new Error(`${filePath} is not a JSON object`);
    }
    return parsed as Record<string, T>;
  }

  async function write(data: Record<string, T>): Promise<void> {
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
    get: (key) => serialize(async () => (await read())[key]),
    set: (key, value) =>
      serialize(async () => {
        const data = await read();
        data[key] = value;
        await write(data);
      }),
    del: (key) =>
      serialize(async () => {
        const data = await read();
        delete data[key];
        await write(data);
      }),
    list: () => serialize(async () => Object.keys(await read())),
  };
}
