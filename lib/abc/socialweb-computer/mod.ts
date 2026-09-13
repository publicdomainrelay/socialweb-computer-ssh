import type { AuthorizedAccount, PresentedKey } from "@publicdomainrelay/socialweb-computer-common";

export interface KeyAuthorizer {
  authorize(username: string, key: PresentedKey): Promise<AuthorizedAccount | null>;
}

export interface CommandIo {
  write(chunk: Uint8Array): void;
  writeErr(chunk: Uint8Array): void;
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

export interface SessionLease {
  sessionPath: string;
}

export interface OAuthSessionSource {
  withSessionFor<T>(did: string, fn: (lease: SessionLease) => Promise<T>): Promise<T>;
}

export interface SshAuthContext {
  username: string;
  key: PresentedKey;
}

export interface SshServerConfig {
  port: number;
  hostname: string;
  hostKeyPath: string;
  banner?: string;
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
