export const BADGE_BLUE_KEYS_NSID = "com.publicdomainrelay.temp.badgeBlueKeys";
export const REQUESTER_ASSOCIATE_SERVICE = "requester_associate";
export const PDS_SERVICE_ID = "#atproto_pds";

export const LC_ENV_PREFIX = "LC_";

export const DEFAULT_POLICY = "tangled-vouch";
export const DEFAULT_POLICY_ARGS: Record<string, unknown> = { firstFree: true };

export const LC_POLICY = "LC_POLICY";
export const LC_POLICY_ARGS = "LC_POLICY_ARGS";
export const LC_POLICY_FIRST_FREE = "LC_POLICY_FIRST_FREE";
export const LC_POLICY_BID_WINDOW_SEC = "LC_POLICY_BID_WINDOW_SEC";
export const LC_VM_NAME = "LC_VM_NAME";
export const LC_SECRETS = "LC_SECRETS";

/**
 * The portable OAuth session the rest of the polyrepo exchanges: what
 * qr.fedfork.com hands out, what hono-pds's session injector mints, and what
 * request-vm-ssh reads with --atproto-oauth-qr --oauth-session-file. Duplicated
 * from @publicdomainrelay/oauth-server-common so this leaf layer stays free of
 * project-local imports.
 */
export interface OAuthSessionData {
  accessJwt: string;
  refreshJwt: string;
  userDid: string;
  handle: string;
  pds: string;
  dpopPublicJwk: Record<string, string>;
  dpopPrivateJwk: Record<string, string>;
  dpopNonce?: string;
  /**
   * The client_id this session was issued to. Optional because the rest of the
   * polyrepo does not carry it, but a refresh token is bound to the client that
   * obtained it, so a session that knows its own client_id can be refreshed
   * without the operator having to configure what that was.
   */
  clientId?: string;
}

export interface PresentedKey {
  algo: string;
  key: string;
}

export interface AuthorizedAccount {
  did: string;
  handle: string;
  pds: string;
}

export interface PolicySelection {
  policy: string;
  args: Record<string, unknown>;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

export function splitSshPublicKey(line: string): PresentedKey | null {
  const parts = line.trim().split(/\s+/);
  if (parts.length < 2) return null;
  if (!parts[0] || !parts[1]) return null;
  return { algo: parts[0], key: parts[1] };
}

export function sshKeyMatches(stored: unknown, presented: PresentedKey): boolean {
  if (typeof stored !== "string") return false;
  const parsed = splitSshPublicKey(stored);
  if (!parsed) return false;
  return parsed.algo === presented.algo && parsed.key === presented.key;
}

export function xrpcPath(nsid: string, params: Record<string, string>): string {
  const search = new URLSearchParams(params).toString();
  return `/xrpc/${nsid}${search ? `?${search}` : ""}`;
}

export function asRecord(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function isRequesterAssociation(record: unknown, accountDid: string): boolean {
  const rec = asRecord(record);
  if (!rec) return false;
  return rec.challenge === accountDid && rec.service === REQUESTER_ASSOCIATE_SERVICE;
}

export function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const v = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(v)) return true;
  if (["0", "false", "no", "off"].includes(v)) return false;
  return fallback;
}

/**
 * Locale variables that share the `LC_` prefix but describe the *client's*
 * locale, not this door's configuration. Forwarding them exports a locale the
 * guest need not have, and bash answers with
 * "setlocale: LC_ALL: cannot change locale (en_US.UTF-8)". They are not policy
 * inputs, so they are dropped rather than translated.
 */
const LOCALE_VARS = new Set([
  "LC_ALL",
  "LC_CTYPE",
  "LC_NUMERIC",
  "LC_TIME",
  "LC_COLLATE",
  "LC_MONETARY",
  "LC_MESSAGES",
  "LC_PAPER",
  "LC_NAME",
  "LC_ADDRESS",
  "LC_TELEPHONE",
  "LC_MEASUREMENT",
  "LC_IDENTIFICATION",
]);

export function lcEnv(env: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (!name.startsWith(LC_ENV_PREFIX) || !ENV_NAME.test(name)) continue;
    if (LOCALE_VARS.has(name)) continue;
    out[name] = value;
  }
  return out;
}

export function policyFromEnv(env: Record<string, string>): PolicySelection {
  const args: Record<string, unknown> = { ...DEFAULT_POLICY_ARGS };
  const rawArgs = env[LC_POLICY_ARGS];
  if (rawArgs) {
    const parsed = JSON.parse(rawArgs);
    const rec = asRecord(parsed);
    if (!rec) throw new Error(`${LC_POLICY_ARGS} must be a JSON object`);
    Object.assign(args, rec);
  }
  if (env[LC_POLICY_FIRST_FREE] !== undefined) {
    args.firstFree = parseBoolean(env[LC_POLICY_FIRST_FREE], DEFAULT_POLICY_ARGS.firstFree as boolean);
  }
  if (env[LC_POLICY_BID_WINDOW_SEC] !== undefined) {
    const n = Number(env[LC_POLICY_BID_WINDOW_SEC]);
    if (!Number.isFinite(n) || n < 0) throw new Error(`${LC_POLICY_BID_WINDOW_SEC} must be a non-negative number`);
    args.bidWindowSec = n;
  }
  return { policy: env[LC_POLICY] || DEFAULT_POLICY, args };
}

export function renderExecCommand(command: string, env: Record<string, string>): string {
  const vars = lcEnv(env);
  const names = Object.keys(vars);
  if (names.length === 0) return command;
  const assignments = names.map((name) => `${name}=${shellQuote(vars[name])}`).join(" ");
  return `export ${assignments}; ${command}`;
}

export const VM_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/**
 * The guest name a client asked for. It reaches cloud-init, which is why it is
 * restricted to a DNS-label shape rather than passed through.
 */
export function vmNameFromEnv(env: Record<string, string>): string | undefined {
  const vmName = env[LC_VM_NAME];
  if (vmName === undefined) return undefined;
  if (!VM_NAME_PATTERN.test(vmName)) {
    throw new Error(`${LC_VM_NAME} must match ${VM_NAME_PATTERN}`);
  }
  return vmName;
}

export const COCORE_APP_REGISTRATION_NSID = "dev.cocore.app.registration";
export const COCORE_APP_REGISTRATION_RKEY = "self";
export const COCORE_APP_WELL_KNOWN_PATH = "/.well-known/cocore-app.json";

/**
 * What co/core reads to learn which DID an app is, and which hosts its browser
 * may be sent back to.
 *
 * Shaped from co/core's documented example rather than a lexicon: no lexicon
 * for this NSID exists in the polyrepo, and these are the fields that example
 * names. `returnUrls` is the load-bearing one -- co/core refuses a returnUrl
 * whose host has not proved it holds this DID, and the proof is
 * /.well-known/cocore-app.json on that host.
 */
export interface CocoreAppRegistration {
  $type: typeof COCORE_APP_REGISTRATION_NSID;
  name: string;
  website: string;
  description?: string;
  iconUrl?: string;
  returnUrls: string[];
}

export function cocoreAppRegistration(input: {
  name: string;
  website: string;
  returnUrl: string;
  description?: string;
  iconUrl?: string;
}): CocoreAppRegistration {
  return {
    $type: COCORE_APP_REGISTRATION_NSID,
    name: input.name,
    website: input.website,
    ...(input.description ? { description: input.description } : {}),
    ...(input.iconUrl ? { iconUrl: input.iconUrl } : {}),
    returnUrls: [input.returnUrl],
  };
}

/**
 * Whether a stored registration already says what this deployment says.
 *
 * Compared before writing because a commit's rev advances even when the record
 * bytes do not: rewriting on every boot would push a no-op commit at every relay
 * that crawls this PDS, which is noise at exactly the record co/core reads.
 */
export function sameRegistration(a: CocoreAppRegistration | null, b: CocoreAppRegistration): boolean {
  if (!a) return false;
  return a.name === b.name &&
    a.website === b.website &&
    a.description === b.description &&
    a.iconUrl === b.iconUrl &&
    a.returnUrls.length === b.returnUrls.length &&
    a.returnUrls.every((url, i) => url === b.returnUrls[i]);
}

