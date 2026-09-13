import { Command } from "@publicdomainrelay/cli-args-env";
import { createLogger } from "@publicdomainrelay/logger";
import { createServe } from "@publicdomainrelay/serve";
import { SOCIALWEB_COMPUTER_SSH_OAUTH_SCOPE } from "@publicdomainrelay/oauth-scope";
import { createAtprotoKeyAuthorizer } from "@publicdomainrelay/socialweb-computer-atproto";
import { createServerOAuth } from "@publicdomainrelay/socialweb-computer-oauth-atproto";
import { createFileSessionStore, createFsOAuthSessionSource } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import { createRequestVmSshRunner } from "@publicdomainrelay/socialweb-computer-request-vm-ssh";
import { createOAuthWebFactory } from "@publicdomainrelay/hono-factory-socialweb-computer-oauth";
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
await Deno.mkdir(stateDir, { recursive: true });

const sessionStore = createFileSessionStore(`${stateDir}/oauth-sessions.json`);
const sessions = createFsOAuthSessionSource({ sessionStore });

const oauth = createServerOAuth({
  clientId: options.oauthClientId as string,
  redirectUri: options.oauthRedirectUri as string,
  scope: SOCIALWEB_COMPUTER_SSH_OAUTH_SCOPE.join(" "),
  sessionStore,
  plcDirectoryUrl: options.plcDirectoryUrl as string,
});

const authorizer = createAtprotoKeyAuthorizer({
  plcDirectoryUrl: options.plcDirectoryUrl as string,
  cacheTtlMs: (options.associationsCacheTtlSec as number) * 1000,
  log,
});

const runner = createRequestVmSshRunner({
  requesterPath: options.requesterPath as string,
  sessions,
  vmReadyTimeoutSec: options.vmReadyTimeoutSec as number,
  log,
});

const ssh = createSshServer({
  config: {
    port: options.sshPort as number,
    hostname: options.sshHostname as string,
    hostKeyPath: (options.hostKeyPath as string) || `${stateDir}/ssh_host_ed25519_key`,
  },
  authorizer,
  runner,
  defaultCommand: options.defaultCommand as string,
  log,
});

const web = createOAuthWebFactory({ oauth, log });
const serve = createServe({
  logger,
  tcp: { addr: options.serveAddr as string, port: options.httpPort as number },
});
serve.app.route("/", web.createApp());

const sshPort = await ssh.listen();
await serve.beginServe();
log("ready", { sshPort, httpPort: options.httpPort });

async function shutdown(): Promise<void> {
  await ssh.shutdown();
  serve.shutdown();
  Deno.exit(0);
}

Deno.addSignalListener("SIGINT", () => void shutdown());
Deno.addSignalListener("SIGTERM", () => void shutdown());
