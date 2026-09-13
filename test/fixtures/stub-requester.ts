function valueOf(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i >= 0 ? args[i + 1] : undefined;
}

const args = Deno.args;
const sessionPath = valueOf(args, "--oauth-session-path") ?? "";
let session: unknown = null;
try {
  session = JSON.parse(await Deno.readTextFile(sessionPath));
} catch {
  session = null;
}

const summary = {
  argv: args,
  exec: valueOf(args, "--exec") ?? "",
  policy: valueOf(args, "--policy") ?? "",
  policyArgs: JSON.parse(valueOf(args, "--policy-args") ?? "{}"),
  accountDid: valueOf(args, "--atproto-handle") ?? "",
  sessionPath,
  session,
  lcEnv: Object.fromEntries(Object.entries(Deno.env.toObject()).filter(([k]) => k.startsWith("LC_"))),
};

console.log(JSON.stringify(summary));
const exit = /--stub-exit (\d+)/.exec(summary.exec);
Deno.exit(exit ? Number(exit[1]) : 0);
