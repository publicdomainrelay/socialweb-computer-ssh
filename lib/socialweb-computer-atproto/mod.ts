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
  maxCacheEntries?: number;
  maxResponseBytes?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

const MAX_RECORD_PAGES = 20;
const DEFAULT_MAX_CACHE_ENTRIES = 1024;
const DEFAULT_MAX_RESPONSE_BYTES = 1 << 20;

interface CacheEntry {
  account: AuthorizedAccount | null;
  records: Record<string, unknown>[];
  expiresAt: number;
}

// Every fetch this door makes is aimed at a host an unauthenticated caller chose
// (through a username, a DID document, or a redirect). None of them may reach
// the host's own network.
export function isPrivateAddress(address: string): boolean {
  const v4 = address.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (v4) {
    const a = Number(v4[1]);
    const b = Number(v4[2]);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    return a >= 224;
  }
  const lower = address.toLowerCase();
  if (lower === "::" || lower === "::1") return true;
  if (lower.startsWith("fe80") || lower.startsWith("fc") || lower.startsWith("fd")) return true;
  if (lower.startsWith("::ffff:")) return isPrivateAddress(lower.slice("::ffff:".length));
  return false;
}

export async function resolvesToPublicAddress(hostname: string): Promise<boolean> {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname) || hostname.includes(":")) {
    return !isPrivateAddress(hostname.replace(/^\[|\]$/g, ""));
  }
  const lower = hostname.toLowerCase();
  if (
    lower === "localhost" || lower.endsWith(".localhost") || lower.endsWith(".local") ||
    lower.endsWith(".internal")
  ) {
    return false;
  }
  try {
    const [a, aaaa] = await Promise.all([
      Deno.resolveDns(hostname, "A").catch(() => [] as string[]),
      Deno.resolveDns(hostname, "AAAA").catch(() => [] as string[]),
    ]);
    const all = [...a, ...aaaa];
    if (all.length === 0) return false;
    return all.every((address) => !isPrivateAddress(address));
  } catch {
    return false;
  }
}

// redirect: "manual" is the load-bearing part -- validating only the first URL
// lets the target bounce the fetch anywhere with a 302.
export async function fetchGuarded(url: string, maxBytes: number): Promise<string | null> {
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return null;
  }
  const loopback =
    target.protocol === "http:" && ["127.0.0.1", "[::1]", "::1", "localhost"].includes(target.hostname);
  if (target.protocol !== "https:" && !loopback) return null;
  if (!loopback && !(await resolvesToPublicAddress(target.hostname))) return null;

  const res = await fetch(target, {
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
    headers: { accept: "application/json" },
  });
  if (res.status >= 300 && res.status < 400) {
    throw new Error(`${target.origin} tried to redirect the fetch`);
  }
  if (!res.ok) throw new Error(`${res.status} from ${target.origin}`);

  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) throw new Error(`${target.origin} exceeded ${maxBytes} bytes`);
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

export function createAtprotoKeyAuthorizer(opts: KeyAuthorizerOptions = {}): KeyAuthorizer {
  const resolver = new IdResolver({ plcUrl: opts.plcDirectoryUrl ?? "https://plc.directory" });
  const cacheTtlMs = opts.cacheTtlMs ?? 300_000;
  const negativeCacheTtlMs = opts.negativeCacheTtlMs ?? 30_000;
  const maxCacheEntries = opts.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
  const maxResponseBytes = opts.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const cache = new Map<string, CacheEntry>();

  function remember(key: string, entry: CacheEntry): void {
    cache.delete(key);
    cache.set(key, entry);
    while (cache.size > maxCacheEntries) {
      const oldest = cache.keys().next();
      if (oldest.done) break;
      cache.delete(oldest.value);
    }
  }

  async function resolveAccount(username: string): Promise<AuthorizedAccount | null> {
    // A did:web username is handed to the identity resolver, which fetches the
    // host named in the DID itself -- and downgrades to plain http for
    // localhost. That host is checked here, because the resolver's own fetch is
    // not ours to guard.
    if (username.startsWith("did:web:")) {
      const host = decodeURIComponent(username.slice("did:web:".length).split(":")[0] ?? "");
      if (!host || !(await resolvesToPublicAddress(host))) return null;
    }
    const did = username.startsWith("did:")
      ? username
      : (await resolver.handle.resolve(username)) ?? null;
    if (!did) return null;
    const didDoc = await resolver.did.resolve(did);
    if (!didDoc) return null;
    const service = didDoc.service?.find((s) => s.id === PDS_SERVICE_ID);
    const pds = typeof service?.serviceEndpoint === "string" ? service.serviceEndpoint : "";
    if (!pds) return null;
    const aka = didDoc.alsoKnownAs?.[0] ?? "";
    const handle = aka.replace(/^at:\/\//, "") || did;
    return { did, handle, pds };
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
      const text = await fetchGuarded(url.toString(), maxResponseBytes);
      if (text === null) throw new Error(`refused to fetch ${url.origin}`);
      const body = JSON.parse(text) as { records?: Array<{ value?: unknown }>; cursor?: string };
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
    let transient = false;
    try {
      const resolved = await resolveAccount(username);
      if (resolved) {
        records = await listAllRecords(resolved.pds, resolved.did);
        account = resolved;
      }
    } catch (err) {
      // A timeout or a refused fetch says nothing about whether this account has
      // associations, so it must not be remembered as an authoritative "no".
      transient = true;
      opts.log?.("authorize_error", { username, error: String(err) });
    }
    return {
      account,
      records,
      expiresAt: Date.now() + (account || transient ? cacheTtlMs : negativeCacheTtlMs),
    };
  }

  return {
    async authorize(username: string, key: PresentedKey): Promise<AuthorizedAccount | null> {
      let entry = cache.get(username);
      if (!entry || Date.now() >= entry.expiresAt) {
        entry = await load(username);
        remember(username, entry);
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
