import type { SessionStore } from "@atproto/oauth-client";
import type { OAuthSessionSource } from "@publicdomainrelay/socialweb-computer-abc";

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
    try {
      const parsed = JSON.parse(await Deno.readTextFile(filePath));
      return typeof parsed === "object" && parsed !== null ? parsed as Record<string, unknown> : {};
    } catch {
      return {};
    }
  }

  async function write(data: Record<string, unknown>): Promise<void> {
    const dir = filePath.split("/").slice(0, -1).join("/");
    if (dir) await Deno.mkdir(dir, { recursive: true });
    await Deno.writeTextFile(filePath, JSON.stringify(data, null, 2));
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
      const value = (await read())[did];
      return value === undefined ? {} : { [did]: value };
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

  return {
    async withSessionFor<T>(did: string, fn: (lease: { sessionPath: string }) => Promise<T>): Promise<T> {
      const dir = await Deno.makeTempDir({ prefix });
      const sessionPath = `${dir}/session.json`;
      try {
        const snapshot = await opts.sessionStore.snapshot(did);
        if (Object.keys(snapshot).length === 0) {
          throw new Error(`no oauth session stored for ${did}`);
        }
        await Deno.writeTextFile(sessionPath, JSON.stringify(snapshot, null, 2));
        const result = await fn({ sessionPath });
        await opts.sessionStore.merge(did, JSON.parse(await Deno.readTextFile(sessionPath)));
        return result;
      } finally {
        await Deno.remove(dir, { recursive: true }).catch(() => {});
      }
    },
  };
}
