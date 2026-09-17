import { Command } from "@publicdomainrelay/cli-args-env";
import { createLogger, createStructuredLogger, getMinLogLevelFromEnv } from "@publicdomainrelay/logger";
import { createServe } from "@publicdomainrelay/serve";
import { EventBus } from "@publicdomainrelay/event-bus";
import { createStaticFilesApp, type StaticFileEvent } from "@publicdomainrelay/hono-factory-static-files-fs";
import { SOCIALWEB_COMPUTER_SSH_OAUTH_SCOPE } from "@publicdomainrelay/oauth-scope";
import { createAtprotoKeyAuthorizer } from "@publicdomainrelay/socialweb-computer-atproto";
import { createAtprotoSessionVerifier } from "@publicdomainrelay/socialweb-computer-oauth-atproto";
import { createFileSessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { createAccountSessions } from "@publicdomainrelay/socialweb-computer-account-sessions-atproto";
import { createRequestVmSshRunner } from "@publicdomainrelay/socialweb-computer-request-vm-ssh";
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
// One owner per account: it refreshes, and every connection gets a copy it
// never rotates. Refresh tokens are single-use, and on a production
// authorization server a second refresher destroys the session outright.
const sessions = createAccountSessions({
  sessionStore,
  clientId: options.oauthClientId as string | undefined,
  log,
});

const authorizer = createAtprotoKeyAuthorizer({
  plcDirectoryUrl: options.plcDirectoryUrl as string,
  cacheTtlMs: (options.associationsCacheTtlSec as number) * 1000,
  log,
});

const requesterArgs = ((options.requesterArg ?? []) as (string | string[])[])
  .flatMap((v) => Array.isArray(v) ? v : v.split(","))
  .map((s) => s.trim())
  .filter(Boolean);

// The session the web app deposits was issued to this deployment's client, so
// the requester has to refresh as that client rather than its own default.
if (options.oauthClientId) {
  requesterArgs.push("--oauth-session-client-id", options.oauthClientId as string);
}

const runner = createRequestVmSshRunner({
  requesterPath: options.requesterPath as string,
  sessions,
  vmReadyTimeoutSec: options.vmReadyTimeoutSec as number,
  sessionMaxSec: options.sessionMaxSec as number,
  extraArgs: requesterArgs,
  log,
});

const ssh = createSshServer({
  config: {
    port: options.sshPort as number,
    hostname: options.sshHostname as string,
    hostKeyPath: (options.hostKeyPath as string) || `${stateDir}/ssh_host_ed25519_key`,
    maxConnections: options.maxConnections as number,
    maxSessions: options.maxSessions as number,
    sessionsPerAccount: options.sessionsPerAccount as number,
  },
  authorizer,
  runner,
  defaultCommand: options.defaultCommand as string,
  log,
});

const web = createWebFactory({
  sessionStore,
  verifier: createAtprotoSessionVerifier(),
  scope: SOCIALWEB_COMPUTER_SSH_OAUTH_SCOPE.join(" "),
  log,
});

const bus = new EventBus<StaticFileEvent>();
bus.subscribe((event) => {
  if (event.type === "file-not-found") logger.warn("web_404", { path: event.path });
});
const staticApp = createStaticFilesApp(options.webDir as string, createStructuredLogger("web", getMinLogLevelFromEnv()), bus);

const serve = createServe({
  logger,
  tcp: { addr: options.serveAddr as string, port: options.httpPort as number },
});
// The API is registered first so /session and the metadata document never reach
// the static handler; everything else falls through to the SPA.
serve.app.route("/", web.createApp());
serve.app.route("/", staticApp as never);

const sshPort = await ssh.listen();
await serve.beginServe();
log("ready", { sshPort, httpPort: options.httpPort, webDir: options.webDir });

async function shutdown(): Promise<void> {
  await ssh.shutdown();
  await sessions.shutdown();
  serve.shutdown();
  Deno.exit(0);
}

Deno.addSignalListener("SIGINT", () => void shutdown());
Deno.addSignalListener("SIGTERM", () => void shutdown());
