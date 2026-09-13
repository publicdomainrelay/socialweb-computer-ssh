import { assert, assertEquals } from "@std/assert";
import { buildRequesterArgs } from "@publicdomainrelay/socialweb-computer-common";

const REQUESTER_CLI = new URL("../../atproto-market/request-vm-ssh/cli-args-env.ts", import.meta.url);
const REQUESTER_MOD = new URL("../../atproto-market/request-vm-ssh/mod.ts", import.meta.url);

function declaredFlags(source: string): Set<string> {
  const flags = new Set<string>();
  for (const match of source.matchAll(/^ {4}"([a-z0-9-]+)":/gm)) flags.add(`--${match[1]}`);
  return flags;
}

Deno.test("every flag this repo emits is declared by request-vm-ssh", async () => {
  const source = await Deno.readTextFile(REQUESTER_CLI);
  const declared = declaredFlags(source);
  assert(declared.size > 20, `expected to parse request-vm-ssh's option table, got ${declared.size}`);

  const args = buildRequesterArgs({
    requesterPath: REQUESTER_MOD.pathname,
    sessionPath: "/tmp/lease/session.json",
    accountDid: "did:plc:a",
    policy: "tangled-vouch",
    policyArgs: { firstFree: true },
    execCommand: "true",
  });
  const emitted = args.filter((a) => a.startsWith("--"));
  const missing = emitted.filter((flag) => !declared.has(flag));
  assertEquals(missing, []);
});

Deno.test("request-vm-ssh runs the session file this repo leases", async () => {
  const source = await Deno.readTextFile(REQUESTER_CLI);
  assert(source.includes('"oauth-session-path"'), "request-vm-ssh must read --oauth-session-path");
  assert(source.includes('"atproto-oauth"'), "request-vm-ssh must support --atproto-oauth");
  assert(source.includes('"skip-qr"'), "request-vm-ssh must support --skip-qr");
});
