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
- **Web app** (browser, no server-side session) runs the AT Protocol OAuth flow
  itself, registers SSH public keys as those records, and deposits the resulting
  session so the SSH half can use it. Modelled on did-key-associator.
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

## The web app

`web/` is a did-key-associator-shaped single page: plain ES modules and web
components, no build step, no framework, no CDN. It runs PAR + PKCE + DPoP
against the account's own PDS and writes the key records itself, so **the
server holds no session cookie, has no login route, and never sees a browser
credential.** Login is bound to the browser that started it by `sessionStorage`,
which is what makes a replayed callback useless.

The scope it asks for is not written by hand: `scripts/generate-web-scope.ts`
emits `web/generated/oauth-scope.js` from
`typescript-helpers/lib/oauth-scope`, and CI fails if the committed copy drifts
from the registry.

Its one server endpoint is `POST /session`, which the page calls after signing
in. It is unauthenticated by nature — the session blob *is* the credential — so
the blob is proved against its own PDS with a live DPoP-bound
`com.atproto.server.getSession` before anything is stored, and the DID that call
confirms is the one it is stored under. A deposit therefore costs a real round
trip, and a blob claiming someone else's DID is stored under its own.

## The session handoff

The session is the polyrepo's portable form — what qr.fedfork.com hands out,
what hono-pds's `sessionInjector` mints, and what `request-vm-ssh` reads with
`--atproto-oauth-qr --oauth-session-file`: access and refresh JWT, user DID,
handle, PDS URL, and the DPoP key as plain JWKs.

```
oauth-sessions.json        (this repo's store, keyed by DID)
  -> <tmpdir>/session.json (one account's session, copied in)
       -> deno run request-vm-ssh --atproto-oauth-qr --oauth-session-file <tmpdir>/session.json
  <- <tmpdir>/session.json (rotated tokens copied back)
```

`request-vm-ssh` also has an `--atproto-oauth --oauth-session-path` mode that
reads `@atproto/oauth-client`'s own session store. This repo does not use it:
that store's DPoP entry is a live key object with no `toJSON`, so it does not
survive a JSON round-trip and cannot be restored from a file. The portable
form has no such problem — its DPoP key is a JWK that both sides can import.

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
| `LC_VM_NAME` | VM name (default `compute-<random>`), restricted to `[A-Za-z0-9][A-Za-z0-9._-]{0,62}` because the name is interpolated into the guest's cloud-init. |
| `LC_KEEP_VM` | Keep the VM after the command exits instead of deleting it. |

`LC_SECRETS` is deliberately *not* accepted from a client: it names a file on
the SSH host, so honouring it would let any authenticated account read host
files into a VM it controls. Operators pass it themselves with
`--requester-arg --secrets=/path/to/secrets.json`.

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

## Trust boundaries

Both halves of this service are reachable by anyone on the network, so:

- **The signature is verified, not just the key.** `ssh2` hands the presented
  signature to the application and never checks it; a public key alone is
  public — it sits in an unauthenticated PDS record — so matching key material
  is not proof of anything. `verifyPublicKeySignature` checks the signed blob
  against the presented key.
- **There is no account cookie and no server-side login.** The browser holds
  the session; the server only ever receives a session blob it has proved
  against the PDS it names.
- **An authenticated client still makes this host resolve names.** The account
  lookup is cached per account and bounded, and the fetch itself is guarded, but
  a client presenting many distinct usernames still causes that many DID
  resolutions.
- **Probes do no work.** An SSH publickey request with no signature proves
  nothing, so it is answered without touching the network; otherwise an
  unauthenticated caller could make this host resolve names and read a PDS of
  their choosing.
- **Every caller-chosen fetch is guarded.** Redirects are refused rather than
  followed, responses are size-capped, and a host resolving into private space
  is not fetched — including for `did:web` usernames, which the identity
  resolver would otherwise fetch (and downgrade to plain http for localhost).
- **The requester does not inherit this process's environment.** It reads any
  option it was not given from its own environment, so inheriting would have
  turned a deployment's `SECRETS_FILE`, `USER_DATA`, or `SSH_AUTHORIZED_KEY`
  into every client's provisioning configuration.
- **The client picks its own fulfillment policy, by design.** `LC_POLICY` and
  `LC_POLICY_ARGS` reach the RFP the client is paying for; that is product, not
  a boundary. Everything else a client can influence is listed under
  [`LC_` environment variables](#lc_-environment-variables).
- **A client that disconnects mid-provision is not killed**, because the
  requester only submits `vm.delete` if it reaches the end of its flow —
  killing it is what would leak the VM. It is instead bounded by
  `--session-max-sec`.

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
deno task test        # fast, self-contained
deno task test:live   # provisions a real VM; needs a container runtime
```

| File | Covers |
|---|---|
| `test/ssh_flow_test.ts` | Fake PLC + PDS, a real `requester_associate` record, a real SSH connection, and a real subprocess spawn. An associated key is accepted, unassociated keys are rejected, `LC_` variables reach the requester's argv and the guest command, and the requester's exit code survives the trip back. |
| `test/ssh_auth_test.ts` | Signature verification: a valid signature passes, a signature over another blob, another key's signature, garbage, a missing blob, and an unparseable key are all refused; a probe with no signature passes. |
| `test/session_lease_test.ts` | The tempdir handoff: one account's session in, rotated tokens back, temporary directory removed on success and on failure, a failed requester still keeping a rotated token, two leases for one account serializing, an unreadable store erroring rather than reading as empty, and the store written `0600`. |
| `test/oauth_web_test.ts` | Login redirect, callback cookie, key registration as a `requester_associate` record, malformed keys, delete, and rejection of unsigned, tampered, or foreign-signed cookies. |
| `test/requester_contract_test.ts` | Every flag this repo emits is still declared by `request-vm-ssh`'s option table. |
| `test/common_test.ts` | `LC_` parsing, policy defaults, SSH key comparison, requester argv. |
| `test/live_market_test.ts` | **Live.** The whole path against real infrastructure: an ephemeral OAuth-PDS whose session injector mints the requester's session, a fake PLC, a dispatcher, an ephemeral atproto-relay, a bidder subprocess running the local container compute provider, and a guest provisioned from cloud-init. The test registers the SSH key as a `requester_associate` record, connects over SSH, and asserts the command ran in the guest and the guest was destroyed. |

`live_market_test.ts` needs a container runtime (Apple `container` on darwin,
docker elsewhere) and skips loudly without one. It runs the ephemeral
atproto-relay in-process, which needs `--unstable-kv` — hence the separate
task rather than a plain file in `test/`.

## Status

In development.
