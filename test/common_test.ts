import { assertEquals, assertThrows } from "@std/assert";
import {
  buildRequesterArgs,
  isRequesterAssociation,
  lcEnv,
  policyFromEnv,
  renderExecCommand,
  requesterArgsFromEnv,
  shellQuote,
  sshKeyMatches,
  splitSshPublicKey,
} from "@publicdomainrelay/socialweb-computer-common";

const KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0example";

Deno.test("splitSshPublicKey drops the comment and rejects fragments", () => {
  assertEquals(splitSshPublicKey(`${KEY} john@host`), { algo: "ssh-ed25519", key: "AAAAC3NzaC1lZDI1NTE5AAAAIB0example" });
  assertEquals(splitSshPublicKey(KEY), { algo: "ssh-ed25519", key: "AAAAC3NzaC1lZDI1NTE5AAAAIB0example" });
  assertEquals(splitSshPublicKey("ssh-ed25519"), null);
  assertEquals(splitSshPublicKey(""), null);
});

Deno.test("sshKeyMatches compares key material, not the comment", () => {
  const presented = splitSshPublicKey(KEY)!;
  assertEquals(sshKeyMatches(`${KEY} other@host`, presented), true);
  assertEquals(sshKeyMatches(KEY, presented), true);
  assertEquals(sshKeyMatches("ssh-rsa AAAAB3NzaC1yc2E", presented), false);
  assertEquals(sshKeyMatches(undefined, presented), false);
});

Deno.test("isRequesterAssociation requires the account as challenge", () => {
  const record = { keyId: KEY, challenge: "did:plc:a", service: "requester_associate" };
  assertEquals(isRequesterAssociation(record, "did:plc:a"), true);
  assertEquals(isRequesterAssociation(record, "did:plc:b"), false);
  assertEquals(isRequesterAssociation({ ...record, service: "bidder_associate" }, "did:plc:a"), false);
  assertEquals(isRequesterAssociation(null, "did:plc:a"), false);
});

Deno.test("policyFromEnv defaults to tangled-vouch with firstFree", () => {
  assertEquals(policyFromEnv({}), { policy: "tangled-vouch", args: { firstFree: true } });
  assertEquals(
    policyFromEnv({ LC_POLICY: "only-me", LC_POLICY_FIRST_FREE: "false", LC_POLICY_BID_WINDOW_SEC: "5" }),
    { policy: "only-me", args: { firstFree: false, bidWindowSec: 5 } },
  );
  assertEquals(
    policyFromEnv({ LC_POLICY_ARGS: '{"firstFree":false,"extra":1}', LC_POLICY_FIRST_FREE: "true" }),
    { policy: "tangled-vouch", args: { firstFree: true, extra: 1 } },
  );
  assertThrows(() => policyFromEnv({ LC_POLICY_ARGS: "[1]" }), Error, "must be a JSON object");
  assertThrows(() => policyFromEnv({ LC_POLICY_BID_WINDOW_SEC: "x" }), Error, "non-negative number");
});

Deno.test("lcEnv keeps only LC_ prefixed names", () => {
  assertEquals(lcEnv({ LC_A: "1", PATH: "/bin", LANG: "C" }), { LC_A: "1" });
});

Deno.test("renderExecCommand exports every LC_ var before the command", () => {
  assertEquals(renderExecCommand("echo $LC_A", { LC_A: "x" }), "export LC_A='x'; echo $LC_A");
  assertEquals(renderExecCommand("bash", {}), "bash");
  assertEquals(renderExecCommand("true", { PATH: "/bin" }), "true");
  assertEquals(renderExecCommand("true", { LC_A: "it's" }), "export LC_A='it'\\''s'; true");
});

Deno.test("shellQuote survives embedded quotes", () => {
  assertEquals(shellQuote("plain"), "'plain'");
  assertEquals(shellQuote("a'b"), "'a'\\''b'");
});

Deno.test("buildRequesterArgs pins the oauth session and default policy", () => {
  const args = buildRequesterArgs({
    requesterPath: "/repo/request-vm-ssh/mod.ts",
    sessionPath: "/tmp/lease/session.json",
    accountDid: "did:plc:a",
    policy: "tangled-vouch",
    policyArgs: { firstFree: true },
    execCommand: "echo hi",
    vmReadyTimeoutSec: 42,
  });
  assertEquals(args, [
    "run", "-A", "/repo/request-vm-ssh/mod.ts",
    "--atproto-oauth", "--atproto-handle", "did:plc:a",
    "--oauth-session-path", "/tmp/lease/session.json",
    "--skip-qr",
    "--policy", "tangled-vouch",
    "--policy-args", '{"firstFree":true}',
    "--vm-ready-timeout-sec", "42",
    "--exec", "echo hi",
  ]);
});

Deno.test("requesterArgsFromEnv maps only the documented LC_ knobs", () => {
  assertEquals(requesterArgsFromEnv({}), []);
  assertEquals(requesterArgsFromEnv({ LC_VM_NAME: "box" }), ["--vm-name", "box"]);
  assertEquals(requesterArgsFromEnv({ LC_KEEP_VM: "1" }), ["--keep-vm"]);
  assertEquals(requesterArgsFromEnv({ LC_SECRETS: "/tmp/s.json" }), ["--secrets", "/tmp/s.json"]);
  assertEquals(requesterArgsFromEnv({ LC_OTHER: "x" }), []);
});
