import { createJsonFileStore } from "@publicdomainrelay/json-file-store-fs";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";

export interface SessionStore {
  get(did: string): Promise<OAuthSessionData | undefined>;
  set(did: string, session: OAuthSessionData): Promise<void>;
  del(did: string): Promise<void>;
  list(): Promise<string[]>;
  withAccount<T>(did: string, fn: () => Promise<T>): Promise<T>;
}

export interface FileSessionStoreOptions {
  onCorrupt?: (info: { path: string; quarantine: string }) => void;
}

export function createFileSessionStore(filePath: string, opts: FileSessionStoreOptions = {}): SessionStore {
  const locks = new Map<string, Promise<unknown>>();
  const store = createJsonFileStore<OAuthSessionData>(filePath, opts);

  return {
    get: (did) => store.get(did),
    set: (did, session) => store.set(did, session),
    del: (did) => store.del(did),
    list: () => store.list(),

    /**
     * The requester rotates the refresh token, so two operations for one account
     * must not both read the same token: the second would be handed a token the
     * first already consumed. Different accounts still run concurrently.
     *
     * Distinct from the store's own serialization, which orders every operation
     * against the file; this orders one account's operations against each other
     * while leaving other accounts free.
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
