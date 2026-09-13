import { OAuthClient } from "@atproto/oauth-client";
import { IdResolver } from "@atproto/identity";
import { memoryStateStore, webCryptoRuntime } from "@publicdomainrelay/atproto-oauth-helpers";
import type { FileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";

export interface ServerOAuthOptions {
  clientId: string;
  redirectUri: string;
  scope: string;
  sessionStore: FileSessionStore;
  clientName?: string;
  plcDirectoryUrl?: string;
}

export interface RepoRecord {
  uri: string;
  cid: string;
  rkey: string;
  value: Record<string, unknown>;
}

export interface ServerOAuth {
  clientMetadata(): Record<string, unknown>;
  authorize(identifier: string): Promise<string>;
  callback(params: URLSearchParams): Promise<{ did: string }>;
  accountFor(did: string): Promise<{ did: string; handle: string; pds: string } | null>;
  listRecords(did: string, collection: string): Promise<RepoRecord[]>;
  createRecord(did: string, collection: string, record: Record<string, unknown>): Promise<RepoRecord>;
  deleteRecord(did: string, collection: string, rkey: string): Promise<void>;
}

export function createServerOAuth(opts: ServerOAuthOptions): ServerOAuth {
  const idResolver = new IdResolver({ plcUrl: opts.plcDirectoryUrl ?? "https://plc.directory" });

  const client = new OAuthClient({
    responseMode: "query",
    clientMetadata: {
      client_id: opts.clientId,
      application_type: "web",
      dpop_bound_access_tokens: true,
      redirect_uris: [opts.redirectUri],
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      scope: opts.scope,
      token_endpoint_auth_method: "none",
      client_name: opts.clientName ?? "socialweb-computer-ssh",
    },
    stateStore: memoryStateStore(),
    sessionStore: opts.sessionStore.store,
    runtimeImplementation: webCryptoRuntime(),
    identityResolver: {
      resolve: async (identifier: string) => {
        const did = identifier.startsWith("did:")
          ? identifier
          : (await idResolver.handle.resolve(identifier)) ?? identifier;
        const didDoc = await idResolver.did.resolve(did) as Record<string, unknown> | null;
        const handle = ((didDoc?.alsoKnownAs as string[] | undefined)?.[0] ?? "").replace("at://", "");
        return { did, didDoc, handle: handle || "handle.invalid" };
      },
    } as never,
    allowHttp: opts.clientId.startsWith("http://"),
  });

  async function fetchHandlerFor(did: string) {
    const session = await client.restore(did);
    return session.fetchHandler.bind(session);
  }

  async function xrpc(did: string, nsid: string, params: Record<string, string>, init?: RequestInit) {
    const fetchHandler = await fetchHandlerFor(did);
    const url = new URL(`https://xrpc.invalid/xrpc/${nsid}`);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    const res = await fetchHandler(url.toString(), init);
    if (!res.ok) throw new Error(`${nsid} failed: ${res.status} ${await res.text()}`);
    return await res.json() as Record<string, unknown>;
  }

  return {
    clientMetadata: () => client.clientMetadata,

    authorize: async (identifier: string) => String(await client.authorize(identifier, { scope: opts.scope })),

    callback: async (params: URLSearchParams) => {
      const result = await client.callback(params);
      return { did: result.session.did };
    },

    accountFor: async (did: string) => {
      const didDoc = await idResolver.did.resolve(did);
      if (!didDoc) return null;
      const service = didDoc.service?.find((s) => s.id === "#atproto_pds");
      const pds = typeof service?.serviceEndpoint === "string" ? service.serviceEndpoint : "";
      if (!pds) return null;
      const aka = didDoc.alsoKnownAs?.[0] ?? "";
      return {
        did,
        handle: aka.replace(/^at:\/\//, "") || did,
        pds: pds.replace(/\/+$/, ""),
      };
    },

    listRecords: async (did: string, collection: string) => {
      const out: RepoRecord[] = [];
      let cursor: string | undefined;
      do {
        const params: Record<string, string> = { repo: did, collection, limit: "100" };
        if (cursor) params.cursor = cursor;
        const body = await xrpc(did, "com.atproto.repo.listRecords", params);
        for (const rec of (body.records ?? []) as Array<{ uri: string; cid: string; value: Record<string, unknown> }>) {
          out.push({ uri: rec.uri, cid: rec.cid, rkey: rec.uri.split("/").pop() ?? "", value: rec.value });
        }
        cursor = (body.cursor as string) || undefined;
      } while (cursor);
      return out;
    },

    createRecord: async (did: string, collection: string, record: Record<string, unknown>) => {
      const { TID } = await import("@atproto/common-web");
      const rkey = TID.next().toString();
      await xrpc(did, "com.atproto.repo.applyWrites", {}, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ repo: did, writes: [{ action: "create", collection, rkey, record }] }),
      });
      const got = await xrpc(did, "com.atproto.repo.getRecord", { repo: did, collection, rkey });
      return { uri: String(got.uri), cid: String(got.cid ?? ""), rkey, value: record };
    },

    deleteRecord: async (did: string, collection: string, rkey: string) => {
      await xrpc(did, "com.atproto.repo.applyWrites", {}, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ repo: did, writes: [{ action: "delete", collection, rkey }] }),
      });
    },
  };
}
