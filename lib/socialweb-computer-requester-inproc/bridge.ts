import { sshTunnelArgs } from "@publicdomainrelay/requester-xrpc";
import type { CommandIo } from "@publicdomainrelay/socialweb-computer-abc";

/**
 * Run one SSH session to the guest, with the channel as its terminal.
 *
 * The shipped provider uses `stdio: "inherit"`, which is why the CLI has to
 * mute console for the duration -- the session owns the process's own fds. A
 * server cannot do that: the mute is a process global and is not re-entrant.
 * Piping the child's stdio and pumping it to the channel means nothing touches
 * fd 1, so concurrent sessions cannot interfere with each other or with logging.
 *
 * Never rejects. runComputeContract has no try/catch around the SSH step, so a
 * rejection would skip the rest of the flow -- including vm.delete.
 */
export async function runSessionOverChannel(
  privateKeyPath: string,
  fqdn: string,
  program: string,
  io: CommandIo,
  log: (event: string, data?: Record<string, unknown>) => void,
): Promise<number> {
  const args = [...sshTunnelArgs(privateKeyPath, fqdn), `root@${fqdn}`, program];
  const child = new Deno.Command("ssh", {
    args,
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

  const pump = async (stream: ReadableStream<Uint8Array>, write: (c: Uint8Array) => void | Promise<void>) => {
    const reader = stream.getReader();
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) return;
        if (value) await write(value);
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
  log("guest_session_exit", { fqdn, code: status.code });
  return status.code;
}
