# socialweb-computer-ssh

SSH front door for the social web computer. Connect with an SSH key that has
been associated with an AT Protocol account, and the connection provisions a
fresh compute VM through the [compute market](../atproto-market) — the command
you typed runs inside that VM, and the VM is torn down when it exits.

```
ssh client
  -> socialweb-computer-ssh        (this repo: SSH server + OAuth HTTP server)
       -> badgeBlueKeys lookup     (requester_associate association for the key)
       -> deno run request-vm-ssh  (RFP -> bid -> accept -> cloud-init -> guest)
            -> command runs in the guest, output streams back over SSH
```

## What it does

- **SSH server** accepts public-key authentication and resolves the presented
  key against `com.publicdomainrelay.temp.badgeBlueKeys` records of service
  type `requester_associate` — the association a primary AT Protocol account
  writes when it acknowledges a requester.
- **OAuth HTTP server** runs the AT Protocol OAuth flow so an account can sign
  in, register SSH public keys, and review its associations.
- **Provisioning** shells out through Deno to `request-vm-ssh`, passing the
  OAuth session through a temporary directory.
- **Client options** travel as `LC_` environment variables:

  ```sh
  LC_MY_VAR="secret_value" ssh user@remote_host "echo \$LC_MY_VAR"
  ```

  These carry policy selection and policy arguments as well as plain values
  for the invoked command. Policy mode defaults to `tangled-vouch`; policy
  arguments such as `firstFree` default to `true`.

## The association

An association is one `badgeBlueKeys` record on the signing-in account's PDS:

```json
{
  "$type": "com.publicdomainrelay.temp.badgeBlueKeys",
  "keyId": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5...",
  "name": "laptop",
  "challenge": "did:plc:the-account",
  "service": "requester_associate",
  "createdAt": "2026-01-01T00:00:00.000Z"
}
```

`challenge` is the account the key is bound to, `keyId` is the OpenSSH public
key with its comment stripped, `name` is a human label. The SSH server resolves
the username (handle or DID) to a DID document, reads that account's PDS
records unauthenticated, and accepts the connection only when a record with
`challenge === <account DID>` and `service === "requester_associate"` carries
the presented key material. Key comparison is on the SSH wire bytes — the
comment and key order do not matter.

## The session handoff

`request-vm-ssh` is run with `--atproto-oauth --oauth-session-path <tmp>`, so
the OAuth session reaches it as a file:

```
oauth-sessions.json        (this repo's store, keyed by DID)
  -> <tmpdir>/session.json (one account's session, copied in)
       -> deno run request-vm-ssh --oauth-session-path <tmpdir>/session.json
  <- <tmpdir>/session.json (refreshed tokens copied back)
```

`request-vm-ssh` rotates the refresh token on use, so the lease copies the file
back into the store before the temporary directory is removed. Concurrent
connections for the same account are serialized by the store.

An SSH client that disconnects mid-provision is *not* killed. The requester
runs to completion, its command writes into a closed channel, and it still
submits `vm.delete` — killing it early is what would leak the VM.

## Run

```sh
deno task start -- \
  --requester-path ../atproto-market/request-vm-ssh/mod.ts \
  --oauth-client-id http://localhost \
  --oauth-redirect-uri http://127.0.0.1:8787/oauth/callback
```

The SSH server listens on `127.0.0.1:2222` and the OAuth server on
`127.0.0.1:8787`. State (session store, SSH host key) lands in
`.socialweb-computer-ssh/`.

Register a key:

1. Open <http://127.0.0.1:8787>, sign in with your handle.
2. Paste the contents of `~/.ssh/id_ed25519.pub` and give it a label.
3. Connect:

   ```sh
   ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
       -p 2222 "$(your handle or DID)@127.0.0.1" 'hostname; id -un'
   ```

## `LC_` environment variables

`ssh` forwards environment variables only when the client and server agree; the
`LC_` prefix is the conventional namespace for locale variables that OpenSSH
forwards by default, and this server reads the whole namespace.

| Variable | Effect |
|---|---|
| `LC_POLICY` | Fulfillment policy name. Default `tangled-vouch`. |
| `LC_POLICY_ARGS` | Policy arguments as a JSON object, merged over the defaults. |
| `LC_POLICY_FIRST_FREE` | `firstFree` — accept the first policy-allowed free bid without waiting out the window. Default `true`. |
| `LC_POLICY_BID_WINDOW_SEC` | `bidWindowSec` — seconds to collect bids. |
| `LC_VM_NAME` | VM name (default `compute-<random>`). |
| `LC_KEEP_VM` | Keep the VM after the command exits instead of deleting it. |
| `LC_SECRETS` | Path to a `[{"path","value"}]` secrets file delivered to the guest. |

Server-side `--requester-arg` (repeatable, `flag=value`) passes through to
`request-vm-ssh` — for example `--requester-arg --relay-port=5555` against a
relay you run yourself.

Every `LC_` variable — recognized or not — is also exported into the command's
environment inside the guest, which is how `echo $LC_MY_VAR` works:

```sh
LC_MY_VAR="secret_value" ssh alice.test@host "echo \$LC_MY_VAR"   # -> secret_value
LC_POLICY=only-me ssh alice.test@host "hostname"
```

Non-`LC_` variables are not forwarded.

A `shell` request with no command runs `--default-command` (default `bash`)
without a TTY, and `pty-req` is refused. The guest command runs with piped
stdio, so there is no terminal to allocate; OpenSSH reports the refusal and
continues in cooked mode rather than pretending otherwise.

## Layout

```
lib/common/socialweb-computer-common       wire types, LC_ parsing, requester argv
lib/abc/socialweb-computer                KeyAuthorizer / ComputeCommandRunner / OAuthSessionSource
lib/socialweb-computer-atproto            badgeBlueKeys lookup over a PDS
lib/socialweb-computer-oauth-atproto      server-side AT Protocol OAuth client
lib/socialweb-computer-oauth-session-fs   session store + tempdir lease
lib/socialweb-computer-request-vm-ssh     spawns request-vm-ssh per connection
lib/hono-factory-socialweb-computer-oauth Hono app: login, callback, key registry
lib/socialweb-computer-ssh-ssh2           ssh2 server binding
hono-socialweb-computer-ssh               CLI: serves both
```

## Tests

```sh
deno task test
```

| File | Covers |
|---|---|
| `test/ssh_flow_test.ts` | Fake PLC + PDS, a real `requester_associate` record, a real SSH connection, and a real subprocess spawn. An associated key is accepted, unassociated keys are rejected, `LC_` variables reach the requester's argv and the guest command, and the requester's exit code survives the trip back. |
| `test/session_lease_test.ts` | The tempdir handoff: one account's session in, rotated tokens back, temporary directory removed on success and on failure, concurrent leases not clobbering each other. |
| `test/oauth_web_test.ts` | Login redirect, callback cookie, key registration as a `requester_associate` record, malformed keys, delete. |
| `test/requester_contract_test.ts` | Every flag this repo emits is still declared by `request-vm-ssh`'s option table. |
| `test/common_test.ts` | `LC_` parsing, policy defaults, SSH key comparison, requester argv. |

Not covered: provisioning against a live market. The connection's command runs
in a real guest only when a bidder is reachable — the market's own harness
(`atproto-market/test/bidder_ssh_relay_test.ts`) is the place that exercises it.

## Status

In development.
