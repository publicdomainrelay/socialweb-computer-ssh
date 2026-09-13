import type { CommandIo, ComputeCommandRunner, OAuthSessionSource } from "@publicdomainrelay/socialweb-computer-abc";
import {
  buildRequesterArgs,
  policyFromEnv,
  renderExecCommand,
  requesterArgsFromEnv,
  type AuthorizedAccount,
} from "@publicdomainrelay/socialweb-computer-common";

export interface RequestVmSshRunnerOptions {
  requesterPath: string;
  sessions: OAuthSessionSource;
  denoExecutable?: string;
  vmReadyTimeoutSec?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

export function createRequestVmSshRunner(opts: RequestVmSshRunnerOptions): ComputeCommandRunner {
  const denoExecutable = opts.denoExecutable ?? Deno.execPath();
  const log = opts.log ?? (() => {});

  return {
    async run(
      account: AuthorizedAccount,
      command: string,
      env: Record<string, string>,
      io: CommandIo,
    ): Promise<void> {
      const { policy, args } = policyFromEnv(env);
      const execCommand = renderExecCommand(command, env);
      const extraArgs = requesterArgsFromEnv(env);

      await opts.sessions.withSessionFor(account.did, async ({ sessionPath }) => {
        const childEnv: Record<string, string> = {};
        for (const [name, value] of Object.entries(Deno.env.toObject())) {
          if (!name.startsWith("LC_")) childEnv[name] = value;
        }

        const args2 = buildRequesterArgs({
          requesterPath: opts.requesterPath,
          sessionPath,
          accountDid: account.did,
          policy,
          policyArgs: args,
          execCommand,
          vmReadyTimeoutSec: opts.vmReadyTimeoutSec,
          extraArgs,
        });

        log("requester_spawn", { did: account.did, policy, command });
        const child = new Deno.Command(denoExecutable, {
          args: args2,
          env: childEnv,
          clearEnv: true,
          stdin: "piped",
          stdout: "piped",
          stderr: "piped",
        }).spawn();

        const stdin = child.stdin.getWriter();
        let stdinChain: Promise<void> = Promise.resolve();
        io.onData((chunk) => {
          stdinChain = stdinChain.then(() => stdin.write(chunk)).catch(() => {});
        });
        io.onClose(() => {
          stdinChain = stdinChain.then(() => stdin.close()).catch(() => {});
        });

        const pump = async (stream: ReadableStream<Uint8Array>, write: (c: Uint8Array) => void) => {
          const reader = stream.getReader();
          try {
            while (true) {
              const { done, value } = await reader.read();
              if (done) return;
              if (value) write(value);
            }
          } finally {
            reader.releaseLock();
          }
        };

        const [, , status] = await Promise.all([
          pump(child.stdout, (c) => io.write(c)),
          pump(child.stderr, (c) => io.writeErr(c)),
          child.status,
        ]);

        log("requester_exit", { did: account.did, code: status.code });
        io.exit(status.code);
      });
    },
  };
}
