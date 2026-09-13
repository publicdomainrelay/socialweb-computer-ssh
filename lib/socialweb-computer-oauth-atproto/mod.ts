import { OAuthClient } from "@atproto/oauth-client";
import { IdResolver } from "@atproto/identity";
import { memoryStateStore, webCryptoRuntime } from "@publicdomainrelay/atproto-oauth-helpers";
import { createOAuthAgentFromSession, type AtprotoAgentLike } from "@publicdomainrelay/atproto-helpers";
import type { OAuthSessionData } from "@publicdomainrelay/socialweb-computer-common";
import type { SessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";

export interface ServerOAuthOptions {
  clientId: string;
  redirectUri: string;
  scope: string;
  sessionStore: SessionStore;
  clientName?: string;
  plcDirectoryUrl?: string;
  log?: (event: string, data?: Record<string, unknown>) => void;
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

interface LibrarySession {
  dpopKey: { jwk: Record<string, string> };
  authMethod: string;
  tokenSet: { sub: string; aud: string; access_token: string; refresh_token: string };
}

export function toPortableSession(lib: LibrarySession, handle: string): OAuthSessionData {
  const jwk = lib.dpopKey.jwk;
  const { d: _private, ...publicJwk } = jwk;
  return {
    accessJwt: lib.tokenSet.access_token,
    refreshJwt: lib.tokenSet.refresh_token,
    userDid: lib.tokenSet.sub,
    handle,
    pds: lib.tokenSet.aud,
    dpopPublicJwk: publicJwk,
    dpopPrivateJwk: jwk,
  };
}

export function createServerOAuth(opts: ServerOAuthOptions): ServerOAuth {
  const idResolver = new IdResolver({ plcUrl: opts.plcDirectoryUrl ?? "https://plc.directory" });
  const log = opts.log ?? (() => {});

  // The flow's own session holds a live DPoP key object, which JSON cannot
  // round-trip -- so it stays in memory and is converted to the portable
  // session (plain JWKs) the moment the callback completes.
  const flowSessions = new Map<string, LibrarySession>();

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
    sessionStore: {
      get: async (sub: string) => flowSessions.get(sub) as never,
      set: async (sub: string, value: unknown) => {
        flowSessions.set(sub, value as LibrarySession);
      },
      del: async (sub: string) => {
        flowSessions.delete(sub);
      },
    },
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

  async function accountFor(did: string) {
    const didDoc = await idResolver.did.resolve(did);
    if (!didDoc) return null;
    const service = didDoc.service?.find((s) => s.id === "#atproto_pds");
    const pds = typeof service?.serviceEndpoint === "string" ? service.serviceEndpoint : "";
    if (!pds) return null;
    const aka = didDoc.alsoKnownAs?.[0] ?? "";
    return { did, handle: aka.replace(/^at:\/\//, "") || did, pds: pds.replace(/\/+$/, "") };
  }

  async function agentFor(did: string): Promise<AtprotoAgentLike> {
    const stored = await opts.sessionStore.get(did);
    if (!stored) throw new Error(`no oauth session stored for ${did}`);
    return await createOAuthAgentFromSession(stored as never, {
      saveSession: (updated) => opts.sessionStore.withAccount(did, () => opts.sessionStore.set(did, updated)),
    });
  }

  return {
    clientMetadata: () => client.clientMetadata,

    authorize: async (identifier: string) => String(await client.authorize(identifier, { scope: opts.scope })),

    callback: async (params: URLSearchParams) => {
      const { session } = await client.callback(params);
      const did = session.did;
      const lib = flowSessions.get(did);
      if (!lib) throw new Error(`oauth flow produced no session for ${did}`);
      const account = await accountFor(did);
      const portable = toPortableSession(lib, account?.handle ?? did);
      await opts.sessionStore.withAccount(did, () => opts.sessionStore.set(did, portable));
      flowSessions.delete(did);
      log("oauth_session_stored", { did, handle: portable.handle });
      return { did };
    },

    accountFor,

    listRecords: async (did: string, collection: string) => {
      const agent = await agentFor(did);
      try {
        const result = await agent.listRecords(did, collection, { limit: 100 });
        return result.records.map((r) => ({ uri: r.uri, cid: r.cid, rkey: r.uri.split("/").pop() ?? "", value: r.value }));
      } finally {
        (agent as unknown as { dispose?: () => void }).dispose?.();
      }
    },

    createRecord: async (did: string, collection: string, record: Record<string, unknown>) => {
      const agent = await agentFor(did);
      try {
        const { TID } = await import("@atproto/common-web");
        const rkey = TID.next().toString();
        await agent.applyWrites(did, [{ action: "create", collection, rkey, record } as never]);
        const written = await agent.getRecord(did, collection, rkey);
        return { uri: written?.uri ?? `at://${did}/${collection}/${rkey}`, cid: written?.cid ?? "", rkey, value: record };
      } finally {
        (agent as unknown as { dispose?: () => void }).dispose?.();
      }
    },

    deleteRecord: async (did: string, collection: string, rkey: string) => {
      const agent = await agentFor(did);
      try {
        await agent.applyWrites(did, [{ action: "delete", collection, rkey } as never]);
      } finally {
        (agent as unknown as { dispose?: () => void }).dispose?.();
      }
    },
  };
}
