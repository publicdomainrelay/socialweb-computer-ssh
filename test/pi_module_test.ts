import { assert, assertEquals } from "@std/assert";
import { buildUserData } from "@publicdomainrelay/cloud-init-common";
import { COCORE_CONFIG_PATH, createPiCocoreModule, DEFAULT_PI_MODEL } from "@publicdomainrelay/cloud-init-plugin-pi";

function fileAt(patch: { write_files?: { path: string; permissions?: string; content: string }[] }, path: string) {
  const found = patch.write_files?.find((f) => f.path === path);
  assert(found, `expected ${path} to be written`);
  return found;
}

Deno.test("the module writes a setup script and runs it", () => {
  const patch = createPiCocoreModule()({});

  assertEquals(patch.runcmd, ["/usr/local/bin/setup-pi.sh"]);

  const setup = fileAt(patch, "/usr/local/bin/setup-pi.sh");
  assertEquals(setup.permissions, "0700");
  assert(
    setup.content.includes("npm:@earendil-works/pi-coding-agent install git:github.com/willnewby/pi-cocore"),
    "the plugin install command",
  );
  assert(setup.content.includes('settings.defaultProvider = "cocore"'), "the provider the plugin registers itself under");
  assert(setup.content.includes(DEFAULT_PI_MODEL), "the ternary Bonsai 2 27B");
  assert(setup.content.includes("setup-pi.done"), "idempotent across boots");
});

Deno.test("the settings write merges rather than overwriting", () => {
  // pi records what it installed as `packages` in the same settings.json. Writing
  // our two keys wholesale drops that, and the guest ends up with the extension
  // cloned, the token delivered, and "No API key found for the selected model".
  const setup = fileAt(createPiCocoreModule()({}), "/usr/local/bin/setup-pi.sh");

  assert(setup.content.includes("JSON.parse(Deno.readTextFileSync(path))"), "reads what pi wrote");
  assert(setup.content.includes("Deno.writeTextFileSync(path"), "and writes it back");
  assert(!setup.content.includes("cat > /root/.pi/agent/settings.json"), "never clobbers the file");
});

Deno.test("pi is on PATH as a wrapper over the deno invocation", () => {
  // The guest is meant to be usable, so `pi -p "…"` has to work rather than
  // `deno run -A npm:…`. PATH and DENO_DIR are set in the wrapper because a
  // non-login shell over SSH inherits neither.
  const patch = createPiCocoreModule()({});
  const pi = fileAt(patch, "/usr/local/bin/pi");

  assertEquals(pi.permissions, "0755");
  assert(pi.content.startsWith("#!/usr/bin/env bash"));
  assert(pi.content.includes('exec deno run -A npm:@earendil-works/pi-coding-agent "$@"'), "execs, args forwarded");
  assert(pi.content.includes('PATH="/usr/local/bin:'), "finds deno without a login shell");
  assert(pi.content.includes("DENO_DIR"), "and a cache deno can write to");
});

Deno.test("pi waits for both the install and the credential", () => {
  // Two independent boot steps finish at different times: this module installs
  // the plugin, and the secrets module delivers the key -- which cannot happen
  // until the winning bidder has injected the file its workload-identity
  // exchange reads. The guest accepts SSH as soon as the tunnel is up, so the
  // first command of a session lands in the gap and pi reports "No API key found
  // for the selected model" -- a broken-token message for an unfinished boot.
  const pi = fileAt(createPiCocoreModule()({}), "/usr/local/bin/pi");

  assert(pi.content.includes("[ -f /var/lib/setup-pi.done ]"), "waits for the plugin install");
  assert(pi.content.includes(`[ -f ${COCORE_CONFIG_PATH} ]`), "and for the credential pi actually reads");
  assert(pi.content.includes("sleep 0.1"), "polls finely, so a fast boot is not padded");
  assert(/seq 1 1200/.test(pi.content), "for about two minutes");
  assert(
    pi.content.indexOf("setup-pi.done") < pi.content.indexOf("exec deno"),
    "the wait comes before the exec, or it guards nothing",
  );
});

Deno.test("the module carries no credential", () => {
  // The token belongs to the secrets module. A token written into cloud-init is
  // a token in public data, which is the whole reason this module only makes pi
  // exist and the secrets module hands over the key separately.
  const serialized = JSON.stringify(createPiCocoreModule()({}));
  // The path is expected -- the wrapper waits on that exact file. Strip it, or
  // "cocore-config" reads as a token to the check below.
  const withoutPath = serialized.split(COCORE_CONFIG_PATH).join("");
  assert(!/cocore-[A-Za-z0-9]/.test(withoutPath), "no token in the module");
  assert(!/"apiKey"/.test(withoutPath), "no key field in the module");
  assert(
    serialized.includes(COCORE_CONFIG_PATH) || !serialized.includes(".pi/agent/cocore-config.json"),
    "the key's path is the plugin's, not one this module invents",
  );
});

Deno.test("a caller can override the model without touching the module", () => {
  const patch = createPiCocoreModule({ model: "custom/model", provider: "other" })({});
  const setup = fileAt(patch, "/usr/local/bin/setup-pi.sh");
  assert(setup.content.includes('settings.defaultModel = "custom/model"'));
  assert(setup.content.includes('settings.defaultProvider = "other"'));
  assert(!setup.content.includes(DEFAULT_PI_MODEL));
});

Deno.test("it composes into cloud-init by value, with no registry entry", () => {
  // The point of the module being a value: cloud-init-common has no idea what pi
  // is, and nothing had to be registered for this to work.
  const yaml = buildUserData({
    ctx: { vmName: "vm", ingressProxyHost: "relay.test", audHost: "relay.test" },
    modules: [createPiCocoreModule()],
  });
  assert(yaml.includes("/usr/local/bin/setup-pi.sh"));
  assert(yaml.includes(DEFAULT_PI_MODEL));
});
