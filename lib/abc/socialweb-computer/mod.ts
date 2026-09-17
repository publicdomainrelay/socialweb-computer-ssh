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
