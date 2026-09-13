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
export const LC_KEEP_VM = "LC_KEEP_VM";
export const LC_SECRETS = "LC_SECRETS";
export const LC_EXEC = "LC_EXEC";

export const DEFAULT_VM_READY_TIMEOUT_SEC = 300;

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

export interface RequesterInvocation {
  requesterPath: string;
  sessionPath: string;
  accountDid: string;
  policy: string;
  policyArgs: Record<string, unknown>;
  execCommand: string;
  vmReadyTimeoutSec?: number;
  extraArgs?: string[];
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

export function buildRequesterArgs(invocation: RequesterInvocation): string[] {
  const args = [
    "run",
    "-A",
    invocation.requesterPath,
    "--atproto-oauth",
    "--atproto-handle",
    invocation.accountDid,
    "--oauth-session-path",
    invocation.sessionPath,
    "--skip-qr",
    "--policy",
    invocation.policy,
    "--policy-args",
    JSON.stringify(invocation.policyArgs),
    "--vm-ready-timeout-sec",
    String(invocation.vmReadyTimeoutSec ?? DEFAULT_VM_READY_TIMEOUT_SEC),
    "--exec",
    invocation.execCommand,
  ];
  return args.concat(invocation.extraArgs ?? []);
}

export function requesterArgsFromEnv(env: Record<string, string>): string[] {
  const args: string[] = [];
  if (env[LC_VM_NAME]) args.push("--vm-name", env[LC_VM_NAME]);
  if (env[LC_SECRETS]) args.push("--secrets", env[LC_SECRETS]);
  if (parseBoolean(env[LC_KEEP_VM], false)) args.push("--keep-vm");
  return args;
}
