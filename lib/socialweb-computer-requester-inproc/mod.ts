import { createOAuthAgentFromSession } from "@publicdomainrelay/atproto-helpers";
import { createDefaultATProtoEventStreamsClient } from "@publicdomainrelay/atproto-event-streams-client";
import { applyOAuthAgentToRequesterPDS, createRequesterPDS, createSshSessionProvider, runComputeContract } from "@publicdomainrelay/requester-xrpc";
import type { RequesterPDS, SshSessionProvider } from "@publicdomainrelay/requester-abc";
import type { SessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import type { CommandIo, ComputeCommandRunner } from "@publicdomainrelay/socialweb-computer-abc";
import { createServe } from "@publicdomainrelay/serve";
import type { GuestCapability } from "@publicdomainrelay/guest-capability-abc";
import { loadOrCreateKeyHex } from "@publicdomainrelay/key-file-fs";
import type { AuthorizedAccount } from "@publicdomainrelay/socialweb-computer-common";
import { policyFromEnv, renderExecCommand, vmNameFromEnv } from "@publicdomainrelay/socialweb-computer-common";
import { pollGuestReady, runSessionOverTunnel } from "./bridge.ts";

export interface InProcessRequesterOptions {
  sessionStore: SessionStore;
  /**
   * Persisted secp256k1 hex for the requester's own DID. Created if absent.
   *
   * The attestation key that signs RFPs has to be verifiable, which means it has
   * to be published -- so the requester keeps an ephemeral DID on PLC whose
   * document carries it, exactly as the CLI does. Persisting the key means that
   * DID is registered once rather than per run.
   */
  requesterKeyPath: string;
  plcDirectoryUrl?: string;
  ingressProxyHost?: string;
  relayUrls?: string[];
  vmReadyTimeoutSec?: number;
  /**
   * OAuth client_id to refresh as, when the stored session does not carry one.
   *
   * A refresh token is bound to the client that obtained it. The session
   * deposited by the page normally carries its own client_id; this is the
   * fallback for a session that does not, and must match the metadata document
   * this deployment publishes.
   */
  oauthClientId?: string;
  /** /etc/hosts entries the guest needs to reach this dispatcher. */
  guestHostAliases?: string[];
  /**
   * Write the com.fedproxy.rbac record that authorizes the guest's ssh host
   * key. Off by default: this app's OAuth scope grants badgeBlueKeys only, so
   * the write would be refused. Turning it on means widening the scope.
   */
  rbac?: boolean;
  /**
   * Builds the guest capabilities for one run, for one account.
   *
   * Called inside run() rather than at construction because a capability's
   * prepare() mints its own keypair and mounts its own serve handle, and the
   * secrets capability holds that at module scope -- so one instance serves
   * exactly one contract, while this requester serves every connection from one
   * process. Returning an empty list runs the contract with no capabilities,
   * which is what an account that never paired should get.
   */
  capabilityFor?: (did: string) => Promise<GuestCapability[]>;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

export interface InProcessRequester extends ComputeCommandRunner {
  shutdown(): Promise<void>;
}

const encoder = new TextEncoder();

/**
 * What to tell a client whose command never ran.
 *
 * A run can stop short in ways that are nobody's error and are invisible from
 * the client -- no bidder online, or a policy no bidder satisfies, both look
 * like the connection simply closing. The reason is on stderr because that is
 * all the client sees besides the exit status.
 */
export function explainNoSession(
  outcome: { event?: string; error?: string; sshReady?: boolean },
  ctx: { policy: string; bidWindowSec: unknown; vmReadyTimeoutSec?: number },
): string {
  const window = typeof ctx.bidWindowSec === "number" ? `${ctx.bidWindowSec}s` : "the bid window";
  const lines: string[] = [];

  if (outcome.event === "no_bids") {
    lines.push(
      `No bids arrived within ${window}, so no VM was provisioned and nothing ran.`,
      "",
      "Worth checking:",
      `  - LC_POLICY_BID_WINDOW_SEC (currently ${ctx.bidWindowSec ?? "default"}) gives bidders more time.`,
      `  - LC_POLICY (currently ${ctx.policy}) decides which bids are acceptable; a policy no`,
      "    bidder satisfies looks exactly like this.",
      "  - whether any bidder is online for this market.",
    );
  } else if (outcome.event === "policy_rejected") {
    lines.push(
      "A bid won, but the fulfillment policy rejected it, so no VM was provisioned.",
    );
    if (outcome.error) lines.push(`  ${outcome.error}`);
    lines.push(
      "",
      `Worth checking LC_POLICY (currently ${ctx.policy}) and LC_POLICY_ARGS.`,
    );
  } else if (outcome.sshReady === false) {
    lines.push(
      `A VM was provisioned but its SSH did not come up within ${ctx.vmReadyTimeoutSec ?? "the"} seconds,`,
      "so nothing ran.",
    );
  } else {
    lines.push(
      `Provisioning did not complete (${outcome.event ?? "unknown event"}).`,
    );
    if (outcome.error) lines.push(`  ${outcome.error}`);
  }

  return lines.join("\n") + "\n";
}

export function createInProcessRequester(opts: InProcessRequesterOptions): InProcessRequester {
  const log = opts.log ?? (() => {});
  const plcUrl = opts.plcDirectoryUrl ?? "https://plc.directory";
  const logger = {
    debug: () => {},
    info: (message: string, meta?: Record<string, unknown>) => log(message, meta ?? {}),
    warn: (message: string, meta?: Record<string, unknown>) => log(message, meta ?? {}),
    error: (message: string, meta?: Record<string, unknown>) => log(message, meta ?? {}),
  };
  type Agent = Awaited<ReturnType<typeof createOAuthAgentFromSession>>;
  /**
   * One agent per account, tagged with the refresh token it was built from.
   *
   * The tag is what makes a re-deposit take effect. The page holds the same
   * session and refreshes it too, and every rotation invalidates any agent built
   * from the previous token -- presenting that token is a replay, which the PDS
   * answers by killing the whole session. So the cache is keyed by the token, not
   * just by the account.
   */
  const agents = new Map<string, { refreshJwt: string; agent: Promise<Agent> }>();
  type RequesterPDS = Awaited<ReturnType<typeof createRequesterPDS>>;
  const requesters = new Map<string, Promise<RequesterPDS>>();

  /**
   * One requester per account, built once and reused.
   *
   * It gets its own serve handle rather than sharing the web server's. Mounting
   * onto the web app fails on the second connection -- Hono freezes its router
   * once a request has been dispatched, and the requester mounts long after the
   * server began serving, so `serve.app.route()` throws "Can not add a route
   * since the matcher is already built". One serve per requester is also what
   * the CLI does, one process per run.
   */
  function requesterFor(did: string): Promise<RequesterPDS> {
    let entry = requesters.get(did);
    if (!entry) {
      entry = (async () => {
        const agent = await agentFor(did);
        const requesterServe = createServe({ logger, tcp: { addr: "127.0.0.1", port: 0 } });
        const pds = await createRequesterPDS({
          logger,
          serve: requesterServe,
          privateKeyHex: await loadOrCreateKeyHex(opts.requesterKeyPath),
          plcDirectoryUrl: plcUrl,
          ingressProxyHost: opts.ingressProxyHost,
          label: "socialweb-computer-ssh",
        });
        // The requester's own repo has to be reachable: the fulfillment policy
        // reads records back through its ingress while deciding.
        await pds.beginServe();
        applyOAuthAgentToRequesterPDS(pds, agent as never, { log });
        return pds;
      })();
      requesters.set(did, entry);
      entry.catch(() => requesters.delete(did));
    }
    return entry;
  }

  /**
   * One agent per account, built once and reused.
   *
   * A per-run agent would be a second refresher for a single-use refresh token,
   * and on a production authorization server replaying one deletes the whole
   * session. One long-lived agent per account is also what makes concurrent
   * connections safe: they share one refresh lock instead of racing.
   */
  function agentFor(did: string): Promise<Agent> {
    return (async () => {
      const stored = await opts.sessionStore.get(did);
      if (!stored) throw new Error(`no oauth session stored for ${did}`);

      const cached = agents.get(did);
      if (cached && cached.refreshJwt === stored.refreshJwt) return await cached.agent;

      if (cached) {
        // Retire the superseded agent: its keepalive would otherwise go on
        // refreshing with a token the store has moved past, which is the replay
        // this cache key exists to prevent.
        agents.delete(did);
        void cached.agent
          .then((a) => (a as unknown as { dispose?: () => void }).dispose?.())
          .catch(() => {});
      }

      // A refresh token is bound to the client_id that obtained it, so the
      // session's own client_id wins over the operator's configured one. The
      // session carries it because that is the only place it is knowable: on
      // loopback the page signs in with a `http://localhost?...` virtual
      // metadata document, which the server cannot reconstruct.
      const clientId = stored.clientId ?? opts.oauthClientId;
      const agent = createOAuthAgentFromSession(stored, {
        clientId,
        // The helper rebuilds the session from the token response, which does
        // not echo the client_id, so re-attach it or a restart would lose it.
        saveSession: (updated) => opts.sessionStore.set(did, { ...updated, clientId }),
      });
      agents.set(did, { refreshJwt: stored.refreshJwt, agent });
      agent.catch(() => {
        if (agents.get(did)?.agent === agent) agents.delete(did);
      });
      return await agent;
    })();
  }

  function providerFor(io: CommandIo): SshSessionProvider {
    // Only the keypair still comes from the shipped provider; the session and
    // the readiness poll are in-process over the guest's tunnel.
    const inner = createSshSessionProvider(undefined);
    return {
      generateKeypair: (vmName) => inner.generateKeypair(vmName),
      pollReady: (privateKeyPath, fqdn, timeoutMs) => pollGuestReady(privateKeyPath, fqdn, timeoutMs, log),
      runSession: (privateKeyPath, fqdn, program) => runSessionOverTunnel(privateKeyPath, fqdn, program, io, log),
    };
  }

  return {
    async run(account: AuthorizedAccount, command: string, env: Record<string, string>, io: CommandIo): Promise<void> {
      let eventStreams: { close(): void } | null = null;
      try {
        const { policy, args: policyArgs } = policyFromEnv(env);
        const execCommand = renderExecCommand(command, env);
        const vmName = vmNameFromEnv(env);
        log("requester_start", { did: account.did, policy, commandChars: command.length });

        const pds = await requesterFor(account.did);

        // A capability that cannot be built must not cost the client its session.
        // Whatever it carries is a convenience, and letting a failed read here
        // throw would turn a provisionable run into "provisioning failed" on
        // stderr -- a worse outcome than running without it.
        const capabilities = await opts.capabilityFor?.(account.did)
          .catch((err) => {
            log("capability_build_failed", { did: account.did, error: String(err) });
            return [] as GuestCapability[];
          }) ?? [];

        eventStreams = createDefaultATProtoEventStreamsClient({
          additionalRelays: opts.relayUrls ?? [],
          log: logger,
        }) as unknown as { close(): void };

        const result = await runComputeContract(pds, {
          plcUrl,
          ingressProxyHost: opts.ingressProxyHost,
          relayUrls: opts.relayUrls,
          eventStreams: eventStreams as never,
          execProgram: execCommand,
          vmName,
          vmReadyTimeoutSec: opts.vmReadyTimeoutSec,
          sshProvider: providerFor(io),
          policy: { name: policy, args: policyArgs },
          guestHostAliases: opts.guestHostAliases,
          rbac: opts.rbac ?? false,
          capabilities,
          logger,
        });

        // Exit status is the guest's, and only exists once a guest ran something.
        // When provisioning stopped short there is no status to forward, and
        // `?? 0` used to report that as success: a client whose run never started
        // got exit 0 and one line saying the connection closed. Anything short of
        // a session is now a failure, with the reason on stderr.
        const outcome = result as {
          sshExitCode?: number;
          event?: string;
          error?: string;
          bids?: number;
          sshReady?: boolean;
        };

        if (typeof outcome.sshExitCode === "number") {
          log("requester_done", { did: account.did, code: outcome.sshExitCode });
          io.exit(outcome.sshExitCode);
        } else {
          const explanation = explainNoSession(outcome, {
            policy,
            bidWindowSec: policyArgs.bidWindowSec,
            vmReadyTimeoutSec: opts.vmReadyTimeoutSec,
          });
          log("requester_no_session", {
            did: account.did,
            event: outcome.event,
            error: outcome.error,
            bids: outcome.bids,
            sshReady: outcome.sshReady,
          });
          await io.writeErr(encoder.encode(explanation));
          io.exit(1);
        }
      } catch (err) {
        log("requester_failed", { did: account.did, error: String(err) });
        await io.writeErr(encoder.encode(`provisioning failed: ${String(err)}\n`));
        io.exit(1);
      } finally {
        eventStreams?.close();
      }
    },

    async shutdown(): Promise<void> {
      for (const settled of await Promise.allSettled([...agents.values()].map((e) => e.agent))) {
        if (settled.status === "fulfilled") (settled.value as unknown as { dispose?: () => void }).dispose?.();
      }
      agents.clear();
    },
  };
}
