import { createOAuthAgentFromSession } from "@publicdomainrelay/atproto-helpers";
import { IdResolver } from "@atproto/identity";
import { createDefaultATProtoEventStreamsClient } from "@publicdomainrelay/atproto-event-streams-client";
import { applyOAuthAgentToRequesterPDS, createSshSessionProvider, runComputeContract } from "@publicdomainrelay/requester-xrpc";
import { loadOrGenerateKeypair } from "@publicdomainrelay/market-atproto";
import type { RequesterPDS, SshSessionProvider } from "@publicdomainrelay/requester-abc";
import type { SessionStore } from "@publicdomainrelay/socialweb-computer-oauth-session-fs";
import type { CommandIo, ComputeCommandRunner } from "@publicdomainrelay/socialweb-computer-abc";
import type { AuthorizedAccount } from "@publicdomainrelay/socialweb-computer-common";
import { policyFromEnv, renderExecCommand, requesterArgsFromEnv } from "@publicdomainrelay/socialweb-computer-common";
import { pollGuestReady, runSessionOverTunnel } from "./bridge.ts";

export interface InProcessRequesterOptions {
  sessionStore: SessionStore;
  /** Persisted secp256k1 hex for the attestation keypair. Created if absent. */
  attestationKeyPath: string;
  plcDirectoryUrl?: string;
  ingressProxyHost?: string;
  relayUrls?: string[];
  vmReadyTimeoutSec?: number;
  log?: (event: string, data?: Record<string, unknown>) => void;
}

export interface InProcessRequester extends ComputeCommandRunner {
  shutdown(): Promise<void>;
}

const encoder = new TextEncoder();

/** Load the attestation hex, generating and persisting one on first use. */
async function attestationHex(path: string): Promise<string> {
  const existing = await Deno.readTextFile(path).then((s) => s.trim()).catch(() => "");
  if (existing) return existing;
  const { Secp256k1Keypair } = await import("@atproto/crypto");
  const kp = await Secp256k1Keypair.create({ exportable: true });
  const hex = Array.from(await kp.export()).map((b) => b.toString(16).padStart(2, "0")).join("");
  const dir = path.split("/").slice(0, -1).join("/");
  if (dir) await Deno.mkdir(dir, { recursive: true, mode: 0o700 });
  await Deno.writeTextFile(path, hex, { mode: 0o600 });
  return hex;
}

/**
 * A RequesterPDS with no local repo of its own.
 *
 * In OAuth mode the market identity is the signed-in user, so there is no
 * ephemeral repo to serve and no ingress relay to register: records go to the
 * user's PDS through the agent, and bids arrive over the firehose. The record
 * writers and callBidder are replaced by applyOAuthAgentToRequesterPDS below.
 */
function ephemeralFreePDS(did: string, attestationKp: Awaited<ReturnType<typeof loadOrGenerateKeypair>>, plcUrl: string): RequesterPDS {
  const resolver = new IdResolver({ plcUrl });
  const unused = () => Promise.reject(new Error("replaced by applyOAuthAgentToRequesterPDS"));
  return {
    did,
    attestationKp,
    privateKeyHex: "",
    pendingBids: new Map(),
    relay: { ingressRef: "", ingressUrl: "", ingressHost: "", close() {}, onServe: async () => {} },
    relaySubdomain: "",
    createRepoRecord: unused,
    createSignedRepoRecord: unused,
    callBidder: unused,
    async resolveBidderEndpoint(endpointUrl: string) {
      if (endpointUrl.startsWith("http://") || endpointUrl.startsWith("https://")) {
        const host = new URL(endpointUrl).host;
        return { targetUrl: `${endpointUrl.replace(/\/+$/, "")}/xrpc`, audDid: `did:web:${host}#pdr_temp_market` };
      }
      if (endpointUrl.startsWith("did:")) {
        const [didPart, fragment] = endpointUrl.split("#");
        const doc = await resolver.did.resolve(didPart);
        const svc = doc?.service?.find((s) => s.id === `#${fragment || "pdr_temp_market"}`);
        if (!svc || typeof svc.serviceEndpoint !== "string") return null;
        const ep = svc.serviceEndpoint.replace(/\/+$/, "");
        return { targetUrl: `${ep}/xrpc`, audDid: `did:web:${new URL(ep).host}#pdr_temp_market` };
      }
      return null;
    },
  } as unknown as RequesterPDS;
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
  const agents = new Map<string, Promise<Agent>>();

  /**
   * One agent per account, built once and reused.
   *
   * A per-run agent would be a second refresher for a single-use refresh token,
   * and on a production authorization server replaying one deletes the whole
   * session. One long-lived agent per account is also what makes concurrent
   * connections safe: they share one refresh lock instead of racing.
   */
  function agentFor(did: string): Promise<Agent> {
    let agent = agents.get(did);
    if (!agent) {
      agent = (async () => {
        const stored = await opts.sessionStore.get(did);
        if (!stored) throw new Error(`no oauth session stored for ${did}`);
        return await createOAuthAgentFromSession(stored, {
          saveSession: (updated) => opts.sessionStore.set(did, updated),
        });
      })();
      agents.set(did, agent);
    }
    return agent;
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
        const extraArgs = requesterArgsFromEnv(env);
        void extraArgs;
        log("requester_start", { did: account.did, policy, commandChars: command.length });

        const agent = await agentFor(account.did);
        const attestationKp = await loadOrGenerateKeypair(await attestationHex(opts.attestationKeyPath));
        const pds = ephemeralFreePDS(account.did, attestationKp, plcUrl);
        applyOAuthAgentToRequesterPDS(pds, agent as never, { log });

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
          vmReadyTimeoutSec: opts.vmReadyTimeoutSec,
          sshProvider: providerFor(io),
          policy: { name: policy, args: policyArgs },
          rbac: true,
          logger,
        });

        const code = (result as { sshExitCode?: number }).sshExitCode ?? 0;
        log("requester_done", { did: account.did, code });
        io.exit(code);
      } catch (err) {
        log("requester_failed", { did: account.did, error: String(err) });
        await io.writeErr(encoder.encode(`provisioning failed: ${String(err)}\n`));
        io.exit(1);
      } finally {
        eventStreams?.close();
      }
    },

    async shutdown(): Promise<void> {
      for (const settled of await Promise.allSettled([...agents.values()])) {
        if (settled.status === "fulfilled") (settled.value as unknown as { dispose?: () => void }).dispose?.();
      }
      agents.clear();
    },
  };
}
