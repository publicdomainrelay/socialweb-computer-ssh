import type { AuthorizedAccount, OAuthSessionData, PresentedKey } from "@publicdomainrelay/socialweb-computer-common";

export interface KeyAuthorizer {
  authorize(username: string, key: PresentedKey): Promise<AuthorizedAccount | null>;
}

export interface CommandIo {
  write(chunk: Uint8Array): void | Promise<void>;
  writeErr(chunk: Uint8Array): void | Promise<void>;
  onData(handler: (chunk: Uint8Array) => void): void;
  onClose(handler: () => void): void;
  exit(code: number): void;
}

export interface ComputeCommandRunner {
  run(
    account: AuthorizedAccount,
    command: string,
    env: Record<string, string>,
    io: CommandIo,
  ): Promise<void>;
}

/** Durable per-account storage of the portable OAuth session. */
export interface SessionStore {
  get(did: string): Promise<OAuthSessionData | undefined>;
  set(did: string, session: OAuthSessionData): Promise<void>;
  del(did: string): Promise<void>;
  list(): Promise<string[]>;
  /** Serialize operations for one account; different accounts run concurrently. */
  withAccount<T>(did: string, fn: () => Promise<T>): Promise<T>;
}

/**
 * Hands out a session one connection can use.
 *
 * One sign-in serves every key on an account, so a lease is a *copy* the
 * caller may use freely -- it is not a lock. The owner is the only thing that
 * refreshes: refresh tokens are single-use, and on a production authorization
 * server replaying one destroys the whole session, so a second refresher is
 * not a slow path, it is an outage.
 */
export interface AccountSessions {
  lease(did: string): Promise<OAuthSessionData>;
  /** Release long-lived resources (refresh agents) at shutdown. */
  shutdown(): Promise<void>;
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
