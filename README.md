# socialweb-computer-ssh

SSH front door for the social web computer. Connect with an SSH key that has
been associated with an AT Protocol account, and the connection provisions a
fresh compute VM through the [compute market](../atproto-market) — the command
you typed runs inside that VM, and the VM is torn down when it exits.

```
ssh client
  -> socialweb-computer-ssh        (this repo: SSH server + web app)
       -> badgeBlueKeys lookup     (requester_associate association for the key)
       -> in-process requester     (RFP -> bid -> accept -> cloud-init -> guest)
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
- **Provisioning** runs `request-vm-ssh` **in this process** — no subprocess.
  One agent per account owns the session, so concurrent connections share a
  refresh lock instead of racing a single-use refresh token.
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

One sign-in serves every key on an account, and **the server is the only thing
that refreshes**. The requester runs in-process against one long-lived agent per
account, so concurrent connections share its refresh lock rather than each
holding a copy of a token that can only be spent once.

That is not tidiness. Refresh tokens are single-use, and on a production
authorization server replaying one **deletes the account's session** rather than
just failing. A second rotator is an outage, not a slow path. Connections for one
account run in parallel; nothing is serialized but the refresh itself.

The requester's records are authored by the signed-in user: `requester-xrpc`
takes the market identity from the session, so a run writes to the account's own
PDS and the bids arrive over the firehose.

### The guest session

The SSH session to the guest does not shell out to `ssh`. The guest's tunnel is a
WebSocket; the server opens it directly, wraps it as a duplex stream, and drives
it with `ssh2`'s client. That drops the `ssh` binary, `websocat`, the
ProxyCommand string, and `ensureWebsocat` — which prepends to the process `PATH`,
a bug in a server doing concurrent work.

The policy sandbox runs in a Worker **in this process**, so the server needs
`--unstable-worker-options` (and `--unstable-kv`); see the `start` task.

## Run

```sh
deno task start
```

That is the whole thing. The SSH server listens on `127.0.0.1:2222`, the web app
on `127.0.0.1:8787`, and state (session store, SSH host key) lands in
`.socialweb-computer-ssh/`.

Then, in order:

1. Open <http://127.0.0.1:8787> and sign in with your handle.
2. Paste the contents of `~/.ssh/id_ed25519.pub` and give it a label.
3. Connect:

```sh
ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -p 2222 "$(whoami)@127.0.0.1" 'hostname; id -un'
```

Use your handle or DID as the username, not `$(whoami)` — it is matched against
your `requester_associate` records.

To listen beyond loopback:

```sh
SSH_HOSTNAME=0.0.0.0 SERVE_ADDR=0.0.0.0 deno task start
```

### The OAuth client_id

Nothing to configure for either of the above. The page signs in as a client of
this deployment: off loopback it uses `https://<host>/oauth-client-metadata.json`,
which this server publishes, and on loopback it uses the `http://localhost?...`
form that the AT Protocol OAuth spec defines for development. Either way the
page sends that `client_id` along with the session it deposits, so the SSH half
refreshes as the client the token was issued to.

`--oauth-client-id` is the fallback for a session deposited without one, and must
be the exact URL the authorization server fetches:

```sh
deno task start -- --oauth-client-id https://ssh.example.com/oauth-client-metadata.json
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

`LC_SECRETS` is deliberately *not* accepted from a client: it names a file on
the SSH host, so honouring it would let any authenticated account read host
files into a VM it controls. There is currently no operator-side way to set it
either — the requester runs in-process, so there is no argv to pass it through.

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
lib/common/socialweb-computer-common       wire types, LC_ parsing, the session type
lib/abc/socialweb-computer                KeyAuthorizer / ComputeCommandRunner / SessionStore
lib/socialweb-computer-atproto            badgeBlueKeys lookup over a PDS
lib/socialweb-computer-oauth-atproto      verifies a deposited session against its PDS
lib/socialweb-computer-requester-inproc   runComputeContract in-process + tunnel bridge
lib/socialweb-computer-oauth-session-fs   durable session store
lib/hono-factory-socialweb-computer-oauth Hono app: metadata document, session deposit
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
| `test/common_test.ts` | The pure helpers: `LC_` parsing, policy defaults, SSH key comparison, and that `LC_VM_NAME` cannot carry anything into the guest's cloud-init. |
| `test/guards_test.ts` | The outbound-fetch guards: private and special addresses, internal-looking hostnames refused before resolution, redirects refused rather than followed, and a client's env kept away from the host's own configuration. |
| `test/ssh_auth_test.ts` | Signature verification: a valid signature passes; a signature over another blob, another key's signature, garbage, a missing blob, and an unparseable key are all refused; an unsigned probe is allowed. |
| `test/ssh_flow_test.ts` | A fake PLC and PDS, a real `requester_associate` record, and a real SSH connection. Associated keys are accepted, unassociated ones rejected, `LC_` variables reach the command while non-`LC_` ones do not, and the requester's exit code survives the trip back. |
| `test/oauth_web_test.ts` | The web half: the client metadata document served from the configured scope, a session stored only under the DID its PDS confirmed, and refusals for an unconfirmed session, a non-object body, and an oversized deposit. |
| `test/web_assets_test.ts` | The page ships what the server serves, takes its scope from the generated module rather than a literal, runs the OAuth flow itself, and sends the `client_id` its session was issued to. |
| `test/session_store_test.ts` | The session store: a corrupt file is quarantined rather than silently emptied, and the store is written owner-only. |
| `test/live_market_test.ts` | **Live.** The whole path against real infrastructure: an ephemeral OAuth-PDS whose session injector mints the requester's session, a fake PLC, a dispatcher, an ephemeral atproto-relay, a bidder subprocess running the local container compute provider, and a guest provisioned from cloud-init. The test registers the SSH key as a `requester_associate` record, connects over SSH, and asserts the command ran in the guest and the guest was destroyed. |

`live_market_test.ts` needs a container runtime (Apple `container` on darwin,
docker elsewhere) and skips loudly without one. It runs the ephemeral
atproto-relay in-process, which needs `--unstable-kv` — hence the separate
task rather than a plain file in `test/`.

`.github/workflows/test.yml` runs on every push and pull request: the generated
scope check, a type-check, and the fast tests. `.github/workflows/live.yml` runs
the live end-to-end on a schedule and on demand, provisioning a real guest on a
GitHub runner.

The live job needs `test/fixtures/undici-shim.ts` preloaded. `@atproto-labs/fetch-node`
guards its SSRF protection by reading `process.versions.undici`, which Deno does
not emulate, so the guard rejects the runtime outright on the Linux path that
dependency version takes. Deno's fetch is not undici, so the question is
inapplicable rather than unmet; the shim supplies the field and nothing in the
service depends on it.

## Status

In development.
