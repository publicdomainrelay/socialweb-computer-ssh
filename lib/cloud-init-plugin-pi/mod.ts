import type { UserDataModule, UserDataPatch } from "@publicdomainrelay/cloud-init-common";

/**
 * The ternary Bonsai 2 27B, as co/core names it.
 *
 * The same model `Bonsai-demo/pi.sh` runs locally as a GGUF through llama.cpp,
 * reached here through co/core instead so the inference is billed to whoever
 * asked for the VM.
 */
export const DEFAULT_PI_MODEL = "prism-ml/Ternary-Bonsai-27B-GGUF-Q2_0";

/** The provider id the co/core plugin registers itself under. */
export const DEFAULT_PI_PROVIDER = "cocore";

/**
 * Where the co/core plugin reads its key. Not configurable because the plugin
 * hardcodes it (`join(homedir(), ".pi", "agent")` in its own source); naming it
 * here is how the secrets bundle and the plugin are kept pointed at one file.
 */
export const COCORE_CONFIG_PATH = "/root/.pi/agent/cocore-config.json";

export interface PiCocoreModuleOptions {
  /** pi provider to default to. Defaults to the co/core plugin's own id. */
  provider?: string;
  /** Model to default to. Defaults to the ternary Bonsai 2 27B. */
  model?: string;
  /** Extra args appended to the plugin install, for a pinned ref or a fork. */
  installTarget?: string;
}

/**
 * A user-data module that installs the pi coding agent with the co/core provider
 * plugin and points it at a model.
 *
 * Deliberately a module *value* rather than a registry entry: nothing in
 * cloud-init-common knows what pi or co/core is, and a caller that wants this
 * passes the function straight into `modules`. That keeps the generic composer
 * generic and lets this live where its consumers are.
 *
 * The credential is not here, and must not be. The plugin reads it from
 * `~/.pi/agent/cocore-config.json`, which the `secrets` module delivers; a token
 * written into cloud-init would be a token in public data. This module only has
 * to make pi exist and say which model to default to.
 *
 * Fails loud. A guest whose whole purpose is to run an agent should not come up
 * looking provisioned when the agent is not installed. The install retries,
 * because a boot-time fetch over a fresh network is the flakiest step.
 */
export function createPiCocoreModule(opts: PiCocoreModuleOptions = {}): UserDataModule {
  const provider = opts.provider ?? DEFAULT_PI_PROVIDER;
  const model = opts.model ?? DEFAULT_PI_MODEL;
  const target = opts.installTarget ?? "git:github.com/willnewby/pi-cocore";

  return (): UserDataPatch => ({
    // curl/unzip for the deno installer; ca-certificates so the fetches verify.
    packages: ["curl", "unzip", "ca-certificates"],
    write_files: [
      {
        path: "/usr/local/bin/pi",
        owner: "root:root",
        permissions: "0755",
        // Named plainly because the deno invocation is the fiddly part and the
        // guest is meant to be usable: `pi -p "…"` should just work. PATH and
        // DENO_DIR are set here rather than assumed, since a non-login shell
        // over SSH inherits neither.
        content: `#!/usr/bin/env bash
export PATH="/usr/local/bin:\${PATH}"
export DENO_DIR="\${DENO_DIR:-/root/.cache/deno}"

# Two independent things have to finish before pi can run, and they finish at
# different times. This module installs the plugin and writes the model defaults;
# the secrets module delivers the key to ${COCORE_CONFIG_PATH}, and it cannot
# deliver until the winning bidder has injected the file it exchanges its
# workload identity against -- seconds to tens of seconds later.
#
# The guest accepts SSH as soon as the tunnel is up, so the first command of a
# session lands inside that window and pi reports "No API key found for the
# selected model". That reads as a broken token when the boot simply had not
# finished. Wait for both, and start anyway if they never arrive: a guest whose
# install failed is better off reporting that for itself than hanging here.
for _ in \$(seq 1 1200); do
  [ -f /var/lib/setup-pi.done ] && [ -f ${COCORE_CONFIG_PATH} ] && break
  sleep 0.1
done

exec deno run -A npm:@earendil-works/pi-coding-agent "$@"
`,
      },
      {
        path: "/usr/local/bin/setup-pi.sh",
        owner: "root:root",
        permissions: "0700",
        content: `#!/usr/bin/env bash
set -euo pipefail

STAMP=/var/lib/setup-pi.done
[ -f "\${STAMP}" ] && exit 0

export PATH="/usr/local/bin:\${PATH}"
export DENO_DIR="\${DENO_DIR:-/root/.cache/deno}"

if ! command -v deno >/dev/null 2>&1; then
  curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh
  chmod 755 /usr/local/bin/deno
fi

for attempt in \$(seq 1 5); do
  if deno run -A npm:@earendil-works/pi-coding-agent install ${target} >/dev/null 2>&1; then
    break
  fi
  if [ "\${attempt}" = 5 ]; then
    echo "pi plugin install failed after \${attempt} attempts" >&2
    exit 1
  fi
  echo "pi plugin install failed (attempt \${attempt}); retrying" >&2
  sleep \$((attempt * 5))
done

mkdir -p /root/.pi/agent

# Merge, never overwrite. pi records what it installed as \`packages\` in this
# same file, so writing our two keys wholesale would drop the plugin that was
# just installed -- leaving a guest with the extension on disk, the token on
# disk, and "No API key found for the selected model" when it runs.
deno eval '
const path = "/root/.pi/agent/settings.json";
let settings = {};
try { settings = JSON.parse(Deno.readTextFileSync(path)); } catch { /* first boot */ }
settings.defaultProvider = "${provider}";
settings.defaultModel = "${model}";
Deno.writeTextFileSync(path, JSON.stringify(settings, null, 2) + "\\n");
'

touch "\${STAMP}"
`,
      },
    ],
    runcmd: ["/usr/local/bin/setup-pi.sh"],
  });
}
