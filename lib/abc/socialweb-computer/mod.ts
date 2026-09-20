import type { AuthorizedAccount, OAuthSessionData, PresentedKey } from "@publicdomainrelay/socialweb-computer-common";

export interface KeyAuthorizer {
  authorize(username: string, key: PresentedKey): Promise<AuthorizedAccount | null>;
}

export interface PtySize {
  cols: number;
  rows: number;
}

export interface CommandIo {
  write(chunk: Uint8Array): void | Promise<void>;
  writeErr(chunk: Uint8Array): void | Promise<void>;
  onData(handler: (chunk: Uint8Array) => void): void;
  onClose(handler: () => void): void;
  exit(code: number): void;
  /**
   * Set when the client allocated a pty, so the guest's command gets a terminal
   * too. Absent for a plain `ssh host cmd`, where piped stdio is correct.
   */
  readonly pty?: PtySize;
}

export interface ComputeCommandRunner {
  run(
    account: AuthorizedAccount,
    command: string,
    env: Record<string, string>,
    io: CommandIo,
  ): Promise<void>;
}

export interface VerifiedSession {
  did: string;
  handle: string;
}

export interface SessionVerifier {
  verify(session: OAuthSessionData): Promise<VerifiedSession | null>;
}

export interface SshServerConfig {
  port: number;
  hostname: string;
  hostKeyPath: string;
  banner?: string;
  /**
   * Shown to a connection no key could authenticate.
   *
   * Such a connection is accepted, unlike one whose key is merely not in the
   * list. A client offers its keys in order and stops at the first the server
   * accepts, so accepting an unassociated key would pre-empt the key that would
   * have worked; but a username that cannot name an account has no key that
   * could work, so accepting pre-empts nothing and buys a channel to explain on.
   * Nothing is ever run for it.
   */
  noKeyCouldMatchMessage?: string;
  maxConnections?: number;
  maxSessions?: number;
  sessionsPerAccount?: number;
  maxAuthAttempts?: number;
  authTimeoutMs?: number;
}

export interface SshServerOptions {
  config: SshServerConfig;
  authorizer: KeyAuthorizer;
  runner: ComputeCommandRunner;
  defaultCommand: string;
  log: (event: string, data?: Record<string, unknown>) => void;
}

export interface SshServerHandle {
  listen(): Promise<number>;
  shutdown(): Promise<void>;
}

/**
 * A co/core inference credential belonging to one atmosphere account.
 *
 * Held server-side and reached only through the pairing flow, never through
 * anything the browser deposits: a token that the browser could name is a token
 * the browser could choose.
 */
export interface CocoreToken {
  token: string;
  /** Inference endpoint the token is good against, as co/core reported it. */
  apiBase?: string;
  /** The co/core account that approved the pairing, which need not be the atmosphere account it is filed under. */
  accountDid?: string;
  pairedAt: string;
}

export interface CocorePairingStarted {
  /**
   * Opaque handle for the browser to poll with.
   *
   * Deliberately not the account DID: a poll carrying a DID would let one
   * browser advance or probe another account's pairing, and would cost a PDS
   * round trip to resolve an identity that start already established.
   */
  pairId: string;
  userCode: string;
  verificationUri: string;
  intervalSecs: number;
}

export type CocorePairingStatus = "pending" | "complete" | "denied" | "expired";

export interface CocorePairing {
  /** Begin a pairing for an account whose session the caller has already verified. */
  start(did: string): Promise<CocorePairingStarted>;
  /** Advance one pairing. Resolves to "complete" only once the token is stored. */
  poll(pairId: string): Promise<CocorePairingStatus>;
  /** The stored token for an account, if it ever paired. */
  token(did: string): Promise<CocoreToken | undefined>;
}

