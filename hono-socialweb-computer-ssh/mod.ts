import { Command } from "@publicdomainrelay/cli-args-env";
import { createLogger, createStructuredLogger, getMinLogLevelFromEnv } from "@publicdomainrelay/logger";
import { createServe } from "@publicdomainrelay/serve";
import { EventBus } from "@publicdomainrelay/event-bus";
import { createStaticFilesApp, type StaticFileEvent } from "@publicdomainrelay/hono-factory-static-files-fs";
import { REQUESTER_OAUTH_SCOPE } from "@publicdomainrelay/oauth-scope";
import { createAtprotoKeyAuthorizer } from "@publicdomainrelay/socialweb-computer-atproto";
import { createAtprotoSessionVerifier } from "@publicdomainrelay/socialweb-computer-oauth-atproto";
import { createFileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { createInProcessRequester } from "@publicdomainrelay/socialweb-computer-requester-inproc";
import { createWebFactory } from "@publicdomainrelay/hono-factory-socialweb-computer-oauth";
import { createSshServer } from "@publicdomainrelay/socialweb-computer-ssh-ssh2";
import cliArgsEnv from "./cli-args-env.json" with { type: "json" };

let runtimeConfig: Record<string, unknown> | null = null;
try {
  runtimeConfig = (await import("./config.json", { with: { type: "json" } })).default;
} catch { /* optional */ }

const { options } = await new Command("CONFIG_PATH_HONO_SOCIALWEB_COMPUTER_SSH", cliArgsEnv, runtimeConfig).resolve();

const logger = createLogger({ serviceName: options.label as string });
const log = (event: string, data: Record<string, unknown> = {}) => logger.info(event, data);

const stateDir = options.stateDir as string;
await Deno.mkdir(stateDir, { recursive: true, mode: 0o700 });

const sessionStore = createFileSessionStore(`${stateDir}/oauth-sessions.json`, {
  onCorrupt: ({ path, quarantine }) => logger.error("session_store_corrupt", { path, quarantine }),
});

const authorizer = createAtprotoKeyAuthorizer({
  plcDirectoryUrl: options.plcDirectoryUrl as string,
  cacheTtlMs: (options.associationsCacheTtlSec as number) * 1000,
  log,
});

const relayUrls = ((options.relayUrl as string) || "")
  .split(",").map((s) => s.trim()).filter(Boolean);

const serve = createServe({
  logger,
  tcp: { addr: options.serveAddr as string, port: options.httpPort as number },
});
// The API is registered first so /session and the metadata document never reach
// the static handler; everything else falls through to the SPA.
// In-process: one agent per account owns the session, so concurrent
// connections share a refresh lock instead of racing a single-use token.
const runner = createInProcessRequester({
  sessionStore,
  requesterKeyPath: `${stateDir}/requester-private-key`,
  plcDirectoryUrl: options.plcDirectoryUrl as string,
  ingressProxyHost: options.ingressProxyHost as string,
  relayUrls,
  vmReadyTimeoutSec: options.vmReadyTimeoutSec as number,
  oauthClientId: options.oauthClientId as string | undefined,
  log,
});

// The pre-auth banner stays DISABLED, and there is no post-auth replacement.
//
// ssh2 sends `banner` exactly once, at SERVICE_ACCEPT for ssh-userauth
// (node_modules/ssh2/lib/protocol/Protocol.js:1531), before the client has sent
// a username -- so the server has no key, no handle and no association to decide
// on -- and OpenSSH prints a USERAUTH_BANNER whenever it receives one. A correct
// sign-in therefore got the whole wall of help.
//
// Delivering the same help only to people who need it would mean accepting a key
// that is not associated, purely to have a session to write on. That was tried
// and reverted: ssh offers its keys in order and stops at the first the server
// accepts, so accepting an unassociated key ends authentication before ssh ever
// reaches the key that would have worked. See the rejection branch in
// socialweb-computer-ssh-ssh2. The remaining route is keyboard-interactive's
// INFO_REQUEST, which the client only reaches once publickey is exhausted.

const webOrigin = ((options.publicOrigin as string) || `http://${options.sshHostname}:${options.httpPort}`)
  .replace(/\/+$/, "");
const sshPublicHost = (options.sshPublicHost as string) || new URL(webOrigin).hostname;

// Sent to a connection no key could authenticate: either the username names no
// account (`ssh user@host` without a handle), or it does and the account has no
// SSH keys registered. That is the one case where the door can accept a connection
// in order to explain, because no key could have worked for that username, so
// accepting pre-empts nothing. See unknownAccountMessage on the SSH config.
const noKeyCouldMatchMessage = [
  "",
  "socialweb.computer",
  "",
  "  If you're seeing this you probably didn't pass your handle or don't have",
  "  an ssh key registered to your account, or haven't done the OAuth sign in.",
  "",
  `      ssh your-handle.example.com@${sshPublicHost}`,
  "",
  "  Anything you pass as LC_* gets passed to the VM.",
  "",
  "  There are also special LC_* vars which help you select bidders.",
  "",
  "  - LC_POLICY: tangled-vouch (default), only-me, mutuals.",
  "  - LC_POLICY_FIRST_FREE: firstFree, accept the first policy-allowed free bid without waiting out the window. Defaults to true.",
  "  - LC_POLICY_BID_WINDOW_SEC: bidWindowSec, seconds to collect bids.",
  "  - LC_POLICY_ARGS: Policy arguments as JSON object if not either of the two above.",
  "",
  "  Your SSH key MUST be associated with your Atmosphere account first.",
  `  Associate SSH public keys with your account at ${webOrigin}.`,
  "",
  "  You MUST sign in at least once so that this service can request VMs",
  "  from the compute market on your behalf.",
  "",
].join("\n");

const ssh = createSshServer({
  config: {
    port: options.sshPort as number,
    hostname: options.sshHostname as string,
    hostKeyPath: (options.hostKeyPath as string) || `${stateDir}/ssh_host_ed25519_key`,
    noKeyCouldMatchMessage,
    maxConnections: options.maxConnections as number,
    maxSessions: options.maxSessions as number,
    sessionsPerAccount: options.sessionsPerAccount as number,
    authTimeoutMs: (options.authTimeoutSec as number) * 1000,
  },
  authorizer,
  runner,
  defaultCommand: options.defaultCommand as string,
  log,
});

const web = createWebFactory({
  sessionStore,
  verifier: createAtprotoSessionVerifier({
    log: (reason, data) => log("session_verify_failed", { reason, ...(data ?? {}) }),
  }),
  scope: REQUESTER_OAUTH_SCOPE.join(" "),
  publicOrigin: options.publicOrigin as string | undefined,
  sshPublicHost: options.sshPublicHost as string | undefined,
  log,
});

const bus = new EventBus<StaticFileEvent>();
bus.subscribe((event) => {
  if (event.type === "file-not-found") logger.warn("web_404", { path: event.path });
});
const staticApp = createStaticFilesApp(options.webDir as string, createStructuredLogger("web", getMinLogLevelFromEnv()), bus);

serve.app.route("/", web.createApp());
serve.app.route("/", staticApp as never);

const sshPort = await ssh.listen();
await serve.beginServe();
log("ready", { sshPort, httpPort: options.httpPort, webDir: options.webDir });

async function shutdown(): Promise<void> {
  await ssh.shutdown();
  serve.shutdown();
  Deno.exit(0);
}

Deno.addSignalListener("SIGINT", () => void shutdown());
Deno.addSignalListener("SIGTERM", () => void shutdown());
