import { assertEquals, assertThrows } from "@std/assert";
import {
  vmNameFromEnv,
  isRequesterAssociation,
  lcEnv,
  policyFromEnv,
  renderExecCommand,
  shellQuote,
  sshKeyMatches,
  splitSshPublicKey,
  xrpcPath,
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

Deno.test("lcEnv drops the client's locale, which the guest need not have", () => {
  // These share the LC_ prefix but describe the client's locale rather than this
  // door's configuration. Exporting them into a guest that has no such locale
  // makes bash print "setlocale: LC_ALL: cannot change locale (en_US.UTF-8)".
  assertEquals(
    lcEnv({ LC_ALL: "en_US.UTF-8", LC_CTYPE: "en_US.UTF-8", LC_POLICY: "only-me" }),
    { LC_POLICY: "only-me" },
  );
  // LC_SECRETS is dropped for a different reason -- see its own test -- and
  // everything else in the namespace still travels.
  assertEquals(lcEnv({ LC_MY_VAR: "hello" }), { LC_MY_VAR: "hello" });
});

Deno.test("renderExecCommand exports every LC_ var before the command", () => {
  assertEquals(renderExecCommand("echo $LC_A", { LC_A: "x" }), "export LC_A='x'; echo $LC_A");
  assertEquals(renderExecCommand("bash", {}), "bash");
  assertEquals(renderExecCommand("true", { PATH: "/bin" }), "true");
  assertEquals(renderExecCommand("true", { LC_A: "it's" }), "export LC_A='it'\\''s'; true");
});

Deno.test("xrpcPath stays relative so the session audience supplies the host", () => {
  assertEquals(
    xrpcPath("com.atproto.repo.listRecords", { repo: "did:plc:a", collection: "x" }),
    "/xrpc/com.atproto.repo.listRecords?repo=did%3Aplc%3Aa&collection=x",
  );
  assertEquals(xrpcPath("com.atproto.repo.applyWrites", {}), "/xrpc/com.atproto.repo.applyWrites");
  assertEquals(
    new URL(xrpcPath("com.atproto.repo.getRecord", { rkey: "1" }), "https://pds.test").href,
    "https://pds.test/xrpc/com.atproto.repo.getRecord?rkey=1",
  );
});

Deno.test("shellQuote survives embedded quotes", () => {
  assertEquals(shellQuote("plain"), "'plain'");
  assertEquals(shellQuote("a'b"), "'a'\\''b'");
});

Deno.test("vmNameFromEnv accepts only a DNS-label-shaped name", () => {
  assertEquals(vmNameFromEnv({}), undefined);
  assertEquals(vmNameFromEnv({ LC_VM_NAME: "box" }), "box");
  assertEquals(vmNameFromEnv({ LC_VM_NAME: "compute-a1b2.c3_d4" }), "compute-a1b2.c3_d4");
  assertEquals(vmNameFromEnv({ LC_OTHER: "x" }), undefined);
});

Deno.test("LC_VM_NAME cannot carry anything into the cloud-init template", () => {
  for (const value of [
    "box\nEnvironment=EVIL=1",
    "box\"",
    "box; rm -rf /",
    "box$(id)",
    "box name",
    "-box",
    ".box",
    "box/host",
    "x".repeat(64),
    "",
  ]) {
    assertThrows(() => vmNameFromEnv({ LC_VM_NAME: value }), Error, "must match", `accepted ${JSON.stringify(value)}`);
  }
});

Deno.test("LC_SECRETS reaches nothing, because there is no child to pass it to", () => {
  // It used to name a file the spawned requester would read off this host. With
  // the requester in-process there is no argv to carry it, so a client setting
  // it has no effect -- asserted so a future child cannot reintroduce the hole.
  assertEquals(vmNameFromEnv({ LC_SECRETS: "/etc/shadow" }), undefined);
});
