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
