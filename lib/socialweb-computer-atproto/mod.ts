import { IdResolver } from "@atproto/identity";
import type { KeyAuthorizer } from "@publicdomainrelay/socialweb-computer-abc";
import {
  BADGE_BLUE_KEYS_NSID,
  PDS_SERVICE_ID,
  asRecord,
  isRequesterAssociation,
  sshKeyMatches,
  type AuthorizedAccount,
  type PresentedKey,
} from "@publicdomainrelay/socialweb-computer-common";

export interface KeyAuthorizerOptions {
  plcDirectoryUrl?: string;
  cacheTtlMs?: number;
  negativeCacheTtlMs?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

const MAX_RECORD_PAGES = 20;

interface CacheEntry {
  account: AuthorizedAccount | null;
  records: Record<string, unknown>[];
  expiresAt: number;
}

export function createAtprotoKeyAuthorizer(opts: KeyAuthorizerOptions = {}): KeyAuthorizer {
  const resolver = new IdResolver({ plcUrl: opts.plcDirectoryUrl ?? "https://plc.directory" });
  const cacheTtlMs = opts.cacheTtlMs ?? 300_000;
  const negativeCacheTtlMs = opts.negativeCacheTtlMs ?? 30_000;
  const cache = new Map<string, CacheEntry>();

  async function resolveAccount(username: string): Promise<AuthorizedAccount | null> {
    const did = username.startsWith("did:")
      ? username
      : await resolver.handle.resolve(username) ?? null;
    if (!did) return null;
    const didDoc = await resolver.did.resolve(did);
    if (!didDoc) return null;
    const service = didDoc.service?.find((s) => s.id === PDS_SERVICE_ID);
    const pds = typeof service?.serviceEndpoint === "string" ? service.serviceEndpoint : "";
    if (!pds) return null;
    const endpoint = fetchableEndpoint(pds);
    if (!endpoint) return null;
    const aka = didDoc.alsoKnownAs?.[0] ?? "";
    const handle = aka.replace(/^at:\/\//, "") || did;
    return { did, handle, pds: endpoint };
  }

  function fetchableEndpoint(pds: string): string | null {
    let url: URL;
    try {
      url = new URL(pds);
    } catch {
      return null;
    }
    const loopback = ["127.0.0.1", "[::1]", "::1", "localhost"].includes(url.hostname);
    if (url.protocol === "https:") return url.origin;
    if (url.protocol === "http:" && loopback) return url.origin;
    return null;
  }

  async function listAllRecords(pds: string, did: string): Promise<Record<string, unknown>[]> {
    const records: Record<string, unknown>[] = [];
    const seen = new Set<string>();
    let cursor: string | undefined;
    for (let page = 0; page < MAX_RECORD_PAGES; page++) {
      const url = new URL(`${pds}/xrpc/com.atproto.repo.listRecords`);
      url.searchParams.set("repo", did);
      url.searchParams.set("collection", BADGE_BLUE_KEYS_NSID);
      url.searchParams.set("limit", "100");
      if (cursor) url.searchParams.set("cursor", cursor);
      const res = await fetch(url, { signal: AbortSignal.timeout(15_000) });
      if (!res.ok) throw new Error(`listRecords ${res.status} for ${did}`);
      const body = await res.json() as { records?: Array<{ value?: unknown }>; cursor?: string };
      for (const rec of body.records ?? []) {
        const value = asRecord(rec.value);
        if (value) records.push(value);
      }
      const next = body.cursor || undefined;
      if (!next || seen.has(next)) break;
      seen.add(next);
      cursor = next;
    }
    return records;
  }

  async function load(username: string): Promise<CacheEntry> {
    let account: AuthorizedAccount | null = null;
    let records: Record<string, unknown>[] = [];
    try {
      const resolved = await resolveAccount(username);
      if (resolved) {
        records = await listAllRecords(resolved.pds, resolved.did);
        account = resolved;
      }
    } catch (err) {
      opts.log?.("authorize_error", { username, error: String(err) });
    }
    return {
      account,
      records,
      expiresAt: Date.now() + (account ? cacheTtlMs : negativeCacheTtlMs),
    };
  }

  return {
    async authorize(username: string, key: PresentedKey): Promise<AuthorizedAccount | null> {
      let entry = cache.get(username);
      if (!entry || Date.now() >= entry.expiresAt) {
        entry = await load(username);
        cache.set(username, entry);
      }
      const account = entry.account;
      if (!account) return null;
      const match = entry.records.some(
        (rec) => isRequesterAssociation(rec, account.did) && sshKeyMatches(rec.keyId, key),
      );
      return match ? account : null;
    },
  };
}
