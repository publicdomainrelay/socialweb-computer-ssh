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

export function lcEnv(env: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(env)) {
    if (name.startsWith(LC_ENV_PREFIX) && ENV_NAME.test(name)) out[name] = value;
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
