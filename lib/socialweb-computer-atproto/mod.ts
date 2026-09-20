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
  /**
   * Floor between re-checks of an account whose cached associations did not
   * match. Bounds the cost of the miss re-check: unauthenticated attempts must
   * not each become a fetch against a PDS.
   */
  missRecheckMs?: number;
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
  /**
   * The lookup itself failed -- a timeout, a refused fetch, a handle that could
   * not be resolved. Distinct from "resolved, and this key is not in the list",
   * because only the latter is a fact about the caller's key.
   */
  lookupFailed: boolean;
  /**
   * The username cannot name an account at all -- not "this key is not in the
   * list" and not "the lookup failed". The only case where refusing would
   * achieve nothing, because no key could have matched.
   */
  unknownAccount: boolean;
  expiresAt: number;
  /** When this entry was last loaded, for the miss re-check floor below. */
  checkedAt: number;
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
  const missRecheckMs = opts.missRecheckMs ?? 5_000;
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

  /**
   * Resolve the username to an account, or say why it cannot be one.
   *
   * `"unknown_account"` is an answer, not a failure: the username cannot name an
   * account under any key. `null` is a failure to find out.
   */
  async function resolveAccount(username: string): Promise<AuthorizedAccount | null | "unknown_account"> {
    // A handle is a domain name, so it contains a dot. A username with neither a
    // dot nor a "did:" prefix cannot identify an account whatever key is
    // offered, which makes it the one case where the door can safely accept a
    // connection in order to explain: there is no later key that would have
    // worked, so accepting pre-empts nothing.
    //
    // Deliberately not extended to a handle that fails to resolve. A typo and an
    // unreachable resolver are indistinguishable at this layer, and treating the
    // second as the first is what told a correctly-registered account its key was
    // not associated.
    if (!username.startsWith("did:") && !username.includes(".")) return "unknown_account";

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
    const empty = (lookupFailed: boolean, unknownAccount = false): CacheEntry => ({
      account: null,
      records: [],
      lookupFailed,
      unknownAccount,
      checkedAt: Date.now(),
      expiresAt: Date.now() + negativeCacheTtlMs,
    });

    let resolved: AuthorizedAccount | null | "unknown_account" = null;
    try {
      resolved = await resolveAccount(username);
    } catch (err) {
      opts.log?.("authorize_error", { username, error: String(err) });
      return empty(true);
    }

    // Not resolved is an unknown, not a "no". The identity resolver reports a
    // handle it cannot look up the same way as one that does not exist -- it
    // returns nothing rather than throwing -- so a DNS blip at startup arrives
    // here indistinguishable from a typo. Treating it as an answer is what told
    // a correctly-registered account its key was not associated.
    if (resolved === "unknown_account") return empty(false, true);
    if (!resolved) return empty(true);

    try {
      return {
        account: resolved,
        records: await listAllRecords(resolved.pds, resolved.did),
        lookupFailed: false,
        unknownAccount: false,
        checkedAt: Date.now(),
        expiresAt: Date.now() + cacheTtlMs,
      };
    } catch (err) {
      // Same reasoning: a refused fetch or a timeout is not evidence about this
      // account's associations. Remembered as a failure, on the short window, so
      // the next attempt retries instead of serving a "no" this never
      // established.
      opts.log?.("authorize_error", { username, error: String(err) });
      return empty(true);
    }
  }

  /** Whether this account has any requester association at all, for any key. */
  function hasAnyAssociation(entry: CacheEntry, account: AuthorizedAccount): boolean {
    return entry.records.some((rec) => isRequesterAssociation(rec, account.did));
  }

  function matches(entry: CacheEntry, key: PresentedKey): boolean {
    const account = entry.account;
    if (!account) return false;
    return entry.records.some(
      (rec) => isRequesterAssociation(rec, account.did) && sshKeyMatches(rec.keyId, key),
    );
  }

  return {
    async authorize(username: string, key: PresentedKey): Promise<AuthorizedAccount | null> {
      const now = Date.now();
      let entry = cache.get(username);
      if (!entry || now >= entry.expiresAt) {
        entry = await load(username);
        remember(username, entry);
      }
      // A cached entry that does not match may only mean the account registered
      // this key since it was loaded -- registering a key and connecting with it
      // is one motion, so serving the stale answer would look like the door
      // ignoring a key that is visibly on the PDS. Re-check on a miss, but no
      // more often than missRecheckMs: every attempt here is unauthenticated, so
      // an unbounded re-check turns a failed login into a fetch against someone
      // else's PDS.
      if (!matches(entry, key) && now - entry.checkedAt >= missRecheckMs) {
        entry = await load(username);
        remember(username, entry);
      }
      // Throwing, not returning null. The caller decides what to tell a client,
      // and "your key is not associated with any account" is a claim only a
      // completed lookup can support -- a failed one must not be dressed up as
      // it, or a transient DNS blip sends someone off to re-register a key that
      // was working.
      if (entry.lookupFailed) {
        throw new Error(`association lookup failed for ${username}`);
      }
      // Distinguishable by kind, so the door can tell a username that names no
      // account -- where explaining costs nothing -- from a key that simply is
      // not in the list, where it must keep refusing so the client offers its
      // remaining keys.
      // Two situations where no key the client holds could ever have matched:
      // the username names no account, or the account has no associations at all.
      // Accepting to explain pre-empts nothing in either, because there is no
      // later key that would have worked. A third situation is deliberately NOT
      // here -- an account that does have associations, offered a key that is not
      // among them -- because one of the client's remaining keys may well be, and
      // accepting would stop it being tried.
      const account = entry.account;
      if (entry.unknownAccount || (account && !hasAnyAssociation(entry, account))) {
        throw Object.assign(
          new Error(`${username} has no key that could be associated with it`),
          { kind: "no_key_could_match", reason: entry.unknownAccount ? "no_account" : "no_associations" },
        );
      }
      return matches(entry, key) ? account : null;
    },
  };
}
