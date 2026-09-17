import type { AccountSessions, CommandIo, ComputeCommandRunner } from "@publicdomainrelay/socialweb-computer-abc";
import {
  buildRequesterArgs,
  policyFromEnv,
  renderExecCommand,
  requesterArgsFromEnv,
  type AuthorizedAccount,
} from "@publicdomainrelay/socialweb-computer-common";

export interface RequestVmSshRunnerOptions {
  requesterPath: string;
  sessions: AccountSessions;
  denoExecutable?: string;
  vmReadyTimeoutSec?: number;
  sessionMaxSec?: number;
  extraArgs?: string[];
  log?: (event: string, data?: Record<string, unknown>) => void;
}

// The requester reads every option it was not given on argv from its own
// environment, so inheriting this door's environment would turn a deployment's
// SECRETS_FILE, USER_DATA, SSH_AUTHORIZED_KEY, POLICY_ENGINE and so on into every
// client's provisioning configuration. Only what a child needs to run is passed.
const CHILD_ENV_ALLOWLIST = ["PATH", "HOME", "TMPDIR", "TMP", "TEMP", "TZ", "LANG", "USER", "LOGNAME", "SHELL"];

const MAX_COMMAND_CHARS = 64 * 1024;
const MAX_STDIN_QUEUE_BYTES = 8 * 1024 * 1024;

const encoder = new TextEncoder();

// The requester logs JSON to stdout -- the same stream the guest's command
// writes to. A record shaped like the structured logger's is operator output and
// belongs on stderr; everything else is the guest talking. That keeps host
// paths, lease paths, and stack traces out of the client's stdout.
export function isLogLine(line: string): boolean {
  const trimmed = line.trim();
  if (!trimmed.startsWith("{") || !trimmed.endsWith("}")) return false;
  try {
    const parsed = JSON.parse(trimmed) as Record<string, unknown>;
    return typeof parsed.ts === "string" && typeof parsed.level === "string" && typeof parsed.message === "string";
  } catch {
    return false;
  }
}

export interface RequestVmSshRunner extends ComputeCommandRunner {
  shutdown(): Promise<void>;
}

export function createRequestVmSshRunner(opts: RequestVmSshRunnerOptions): RequestVmSshRunner {
  const denoExecutable = opts.denoExecutable ?? Deno.execPath();
  const log = opts.log ?? (() => {});
  const inFlight = new Set<Deno.ChildProcess>();

  return {
    async run(
      account: AuthorizedAccount,
      command: string,
      env: Record<string, string>,
      io: CommandIo,
    ): Promise<void> {
      if (command.length > MAX_COMMAND_CHARS) {
        await io.writeErr(encoder.encode(`command exceeds ${MAX_COMMAND_CHARS} characters\n`));
        io.exit(1);
        return;
      }

      const { policy, args: policyArgs } = policyFromEnv(env);
      const execCommand = renderExecCommand(command, env);
      const extraArgs = requesterArgsFromEnv(env).concat(opts.extraArgs ?? []);

      // A copy, not a lock: the owner mints it and every connection gets its
      // own. Nothing here writes back -- a child must never be able to rotate
      // the account's refresh token, because a second rotation is fatal.
      const session = await opts.sessions.lease(account.did);
      const leaseDir = await Deno.makeTempDir({ prefix: "socialweb-computer-lease-" });
      await Deno.chmod(leaseDir, 0o700).catch(() => {});
      const sessionPath = `${leaseDir}/session.json`;
      await Deno.writeTextFile(sessionPath, JSON.stringify(session, null, 2), { mode: 0o600 });
      try {
        const childEnv: Record<string, string> = {};
        const hostEnv = Deno.env.toObject();
        for (const name of CHILD_ENV_ALLOWLIST) {
          if (hostEnv[name] !== undefined) childEnv[name] = hostEnv[name];
        }

        const args = buildRequesterArgs({
          requesterPath: opts.requesterPath,
          sessionPath,
          accountDid: account.did,
          policy,
          policyArgs,
          execCommand,
          vmReadyTimeoutSec: opts.vmReadyTimeoutSec,
          extraArgs,
        });

        // Never the command text itself: it is unbounded client input and would
        // land verbatim in the operator's log.
        log("requester_spawn", { did: account.did, policy, commandChars: command.length });

        const child = new Deno.Command(denoExecutable, {
          args,
          env: childEnv,
          clearEnv: true,
          stdin: "piped",
          stdout: "piped",
          stderr: "piped",
        }).spawn();
        inFlight.add(child);

        // A client that walks away mid-run must not hold a VM indefinitely.
        const deadline = opts.sessionMaxSec
          ? setTimeout(() => {
            log("session_max_exceeded", { did: account.did, sessionMaxSec: opts.sessionMaxSec });
            try {
              child.kill("SIGTERM");
            } catch { /* already gone */ }
          }, opts.sessionMaxSec * 1000)
          : null;

        const stdin = child.stdin.getWriter();
        let queued = 0;
        let stdinChain: Promise<void> = Promise.resolve();
        io.onData((chunk) => {
          if (queued > MAX_STDIN_QUEUE_BYTES) return;
          queued += chunk.byteLength;
          stdinChain = stdinChain
            .then(() => stdin.write(chunk))
            .then(() => { queued -= chunk.byteLength; })
            .catch(() => {});
        });
        io.onClose(() => {
          stdinChain = stdinChain.then(() => stdin.close()).catch(() => {});
        });

        const emit = async (line: string, guest: boolean): Promise<void> => {
          const payload = encoder.encode(`${line}\n`);
          if (isLogLine(line)) await io.writeErr(payload);
          else if (guest) await io.write(payload);
          else await io.writeErr(payload);
        };

        const pump = async (stream: ReadableStream<Uint8Array>, guest: boolean): Promise<void> => {
          const reader = stream.getReader();
          const decoder = new TextDecoder();
          let tail = "";
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) break;
              if (!value) continue;
              const lines = (tail + decoder.decode(value, { stream: true })).split("\n");
              tail = lines.pop() ?? "";
              for (const line of lines) await emit(line, guest);
            }
          } finally {
            reader.releaseLock();
          }
          if (tail) await emit(tail, guest);
        };

        try {
          const [, , status] = await Promise.all([
            pump(child.stdout, true),
            pump(child.stderr, false),
            child.status,
          ]);
          log("requester_exit", { did: account.did, code: status.code });
          io.exit(status.code);
        } finally {
          if (deadline !== null) clearTimeout(deadline);
          inFlight.delete(child);
        }
      } finally {
        await Deno.remove(leaseDir, { recursive: true }).catch(() => {});
      }
    },

    async shutdown(): Promise<void> {
      if (inFlight.size === 0) return;
      log("waiting_for_children", { count: inFlight.size });
      const settled = Promise.allSettled([...inFlight].map((child) => child.status));
      const grace = Promise.withResolvers<void>();
      const timer = setTimeout(() => grace.resolve(), 30_000);
      await Promise.race([settled, grace.promise]);
      clearTimeout(timer);
      if (inFlight.size > 0) {
        // Signalling now would abandon VMs mid-provision: the requester only
        // submits vm.delete if it reaches the end of its own flow.
        log("children_still_running_on_shutdown", { count: inFlight.size });
      }
    },
  };
}
