#!/usr/bin/env bash
set -xeuo pipefail

# Deploy this SSH front door to a host.
#
#   ./scripts/deploy.sh
#   SSH_TARGET=root@other.example ORIGIN=ssh.other.example ./scripts/deploy.sh
#
# Every host- or domain-specific value is a variable here; nothing below names a
# particular host. Two deployments on one host need distinct SERVICE_NAME (and
# SERVICE_USER/STATE_DIR_HOST if they should not share state).
#
# The door wants port 22, so the host's own sshd moves to HOST_SSHD_PORT. That
# switch is staged and verified from outside, with a rollback armed while the
# port is in flight -- see the two phases below. Set DOOR_SSH_PORT if 22 has to
# stay with the host's sshd.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ORG_ROOT="$(dirname "$PROJECT_DIR")"

SSH_TARGET="${SSH_TARGET:-root@socialweb.computer}"
ORIGIN="${ORIGIN:-ssh.socialweb.computer}"
SERVICE_NAME="${SERVICE_NAME:-socialweb-computer-ssh}"
SERVICE_USER="${SERVICE_USER:-swc}"
STATE_DIR_HOST="${STATE_DIR_HOST:-/var/lib/${SERVICE_NAME}}"
DOOR_SSH_PORT="${DOOR_SSH_PORT:-22}"
HOST_SSHD_PORT="${HOST_SSHD_PORT:-1997}"
INGRESS_PROXY_HOST="${INGRESS_PROXY_HOST:-xrpc.fedproxy.com}"
# Name shown in the connect example. The apex resolves to the same address as
# ORIGIN, so both reach this door; this is the one worth showing people.
SSH_PUBLIC_HOST="${SSH_PUBLIC_HOST:-socialweb.computer}"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 -o BatchMode=yes"

# The remote side reads these from the command line (heredocs are quoted, so
# nothing expands locally into them) and phase two reads them from the transient
# unit's environment.
REMOTE_ENV="ORIGIN='${ORIGIN}' SERVICE_NAME='${SERVICE_NAME}' SERVICE_USER='${SERVICE_USER}' STATE_DIR_HOST='${STATE_DIR_HOST}' DOOR_SSH_PORT='${DOOR_SSH_PORT}' HOST_SSHD_PORT='${HOST_SSHD_PORT}' INGRESS_PROXY_HOST='${INGRESS_PROXY_HOST}' SSH_PUBLIC_HOST='${SSH_PUBLIC_HOST}'"
REMOTE_SETENV="--setenv=ORIGIN='${ORIGIN}' --setenv=SERVICE_NAME='${SERVICE_NAME}' --setenv=SERVICE_USER='${SERVICE_USER}' --setenv=STATE_DIR_HOST='${STATE_DIR_HOST}' --setenv=DOOR_SSH_PORT='${DOOR_SSH_PORT}' --setenv=HOST_SSHD_PORT='${HOST_SSHD_PORT}' --setenv=INGRESS_PROXY_HOST='${INGRESS_PROXY_HOST}' --setenv=SSH_PUBLIC_HOST='${SSH_PUBLIC_HOST}'"

# sshd keeps HOST_SSHD_PORT, so that is where deploys arrive once the switch has
# happened; before it they arrive on DOOR_SSH_PORT. Probing both means the same
# script works against a fresh host and a switched one without being told which.
DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-}"
if [ -z "$DEPLOY_SSH_PORT" ]; then
  for candidate in "$HOST_SSHD_PORT" "$DOOR_SSH_PORT"; do
    if ssh ${SSH_OPTS} -p "$candidate" "$SSH_TARGET" true >/dev/null 2>&1; then
      DEPLOY_SSH_PORT="$candidate"
      break
    fi
  done
fi
if [ -z "$DEPLOY_SSH_PORT" ]; then
  echo "cannot reach ${SSH_TARGET} on ${HOST_SSHD_PORT} or ${DOOR_SSH_PORT}" >&2
  exit 1
fi
echo "=== deploying ${ORIGIN} (service ${SERVICE_NAME}) over ssh port ${DEPLOY_SSH_PORT} ==="

remote() {
  ssh ${SSH_OPTS} -p "$DEPLOY_SSH_PORT" "$SSH_TARGET" "$@"
}

# ── Stage on remote ────────────────────────────────────────────────────────────
# This service imports its siblings by relative path (@publicdomainrelay/logger
# and friends resolve to ../typescript-helpers, ../atproto-market, ../hono-pds,
# ../did-key-ingress-proxy, ../atproto-relay), so it cannot be deployed as a
# subtree. Ship the org root the same way social-web-computer's deploy does, to
# the same /opt/org-root, so the two agree on what is on the host.
# A deno compile binary is not an option for the same reason as the bidder:
# import.meta.url resolves into the compile VFS, so the local-fs package store
# scans nothing.

echo "=== shipping org-root ==="
tar czf - -C "$ORG_ROOT" \
  --exclude='.git' \
  --exclude='node_modules' \
  --exclude='.codegraph' \
  --exclude='digitalocean-bidder/data' \
  --exclude='social-web-computer/dist' \
  --exclude='social-web-computer/fancy' \
  --exclude='socialweb-computer-ssh/.socialweb-computer-ssh' \
  --exclude='*.tgz' \
  . | remote "rm -rf /opt/org-root && mkdir -p /opt/org-root && tar xzf - -C /opt/org-root"
echo "=== org-root shipped → /opt/org-root ==="

# ── Remote setup ───────────────────────────────────────────────────────────────

remote "${REMOTE_ENV} bash -xe" <<'REMOTE_EOF'

# ── deno runtime (idempotent) ──────────────────────────────────────────────────
# The service runs from source, so it needs the runtime, not a compiled binary.
if ! command -v deno >/dev/null 2>&1; then
  apt-get update && apt-get install -y curl unzip
  curl -fsSL https://deno.land/install.sh | DENO_INSTALL=/usr/local sh
  chmod 755 /usr/local/bin/deno
fi

# ── Service account ────────────────────────────────────────────────────────────
# Still non-root even though it now takes port 22: the unit is granted exactly
# CAP_NET_BIND_SERVICE rather than being handed root to get one privileged bind.
if ! id -u ${SERVICE_USER} >/dev/null 2>&1; then
  useradd --system --create-home \
    --home-dir ${STATE_DIR_HOST} \
    --shell /usr/sbin/nologin ${SERVICE_USER}
fi
install -d -m 700 -o ${SERVICE_USER} -g ${SERVICE_USER} ${STATE_DIR_HOST}

# ── Warm the module cache as the service user ──────────────────────────────────
# Best effort: makes the first start fast instead of racing Restart=always.
# node-modules-dir=none is what lets the unit run without write access to the
# source tree: npm deps resolve from DENO_DIR instead of a node_modules beside
# deno.json. That matters because the org root is re-shipped by
# social-web-computer's deploy with `rm -rf /opt/org-root`, so anything written
# in there is lost and any ownership fixed up here would reset to root.
# runuser rather than sudo: a minimal Debian image has util-linux but not sudo.
runuser -u ${SERVICE_USER} -- env HOME=${STATE_DIR_HOST} \
  DENO_DIR=${STATE_DIR_HOST}/deno \
  /usr/local/bin/deno cache --node-modules-dir=none \
  --unstable-kv --unstable-worker-options \
  --config /opt/org-root/socialweb-computer-ssh/deno.json \
  /opt/org-root/socialweb-computer-ssh/hono-socialweb-computer-ssh/mod.ts || true
chown -R ${SERVICE_USER}:${SERVICE_USER} ${STATE_DIR_HOST}

# ── systemd unit ───────────────────────────────────────────────────────────────
cat > /etc/systemd/system/${SERVICE_NAME}.service <<UNIT
[Unit]
Description=${SERVICE_NAME} — SSH front door for the compute market
After=network.target network-online.target ssh.socket
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
# The working directory must be writable. The fulfillment policy evaluates in
# gha-lite, which creates .cache and .tempdir in Deno.cwd() (workflow.ts), and
# under ProtectSystem=strict the source tree is read-only -- the run then dies
# with "Read-only file system (os error 30): tmpdir" and the policy rejects.
# Hence cwd here, with the config and entrypoint named explicitly.
WorkingDirectory=${STATE_DIR_HOST}
ExecStart=/usr/local/bin/deno run -A --node-modules-dir=none \
  --unstable-kv --unstable-worker-options \
  --config /opt/org-root/socialweb-computer-ssh/deno.json \
  /opt/org-root/socialweb-computer-ssh/hono-socialweb-computer-ssh/mod.ts \
  --ssh-hostname 0.0.0.0 \
  --ssh-port ${DOOR_SSH_PORT} \
  --serve-addr 127.0.0.1 \
  --http-port 8787 \
  --state-dir ${STATE_DIR_HOST} \
  --web-dir /opt/org-root/socialweb-computer-ssh/web \
  --public-origin https://${ORIGIN} \
  --ingress-proxy-host ${INGRESS_PROXY_HOST} \
  --ssh-public-host ${SSH_PUBLIC_HOST}

Environment=HOME=${STATE_DIR_HOST}
Environment=DENO_DIR=${STATE_DIR_HOST}/deno

Restart=always
RestartSec=5
LimitNOFILE=65536

NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
# The state dir holds the session store, the SSH host key and the requester key.
# Nothing else is writable: with node-modules-dir=none the source tree is read
# only, which is why it is absent below.
ReadWritePaths=${STATE_DIR_HOST}

# Exactly one privileged bind, for port 22. AmbientCapabilities keeps it through
# exec, so the process holds no other privilege and NoNewPrivileges still holds.
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable ${SERVICE_NAME}
# Not started yet: port 22 is still sshd's, and starting now would only race
# Restart=always against a bind that cannot succeed. The second phase below
# frees the port and starts it.
REMOTE_EOF

# ── Host sshd: stage 1997 alongside 22 ─────────────────────────────────────────
# Port 22 goes to this service, so the host's sshd moves to 1997. The listener
# is socket-activated, so the port lives in ssh.socket -- adding "Port 1997" to
# sshd_config would look correct and change nothing.
#
# Staged rather than switched: 1997 is added while 22 is still served, so there
# is always a way in. The switch is verified from outside before 22 is released,
# which matters because this script itself arrives over that port.
#
# The restart ends this session: ssh.service has RequiredBy=ssh.socket, so
# restarting the socket stops the sshd carrying the heredoc. Everything needed
# is written before it, and the failure is swallowed -- the check below is the
# real gate, not the exit code.
#
# Skipped entirely once 22 already belongs to this service. Re-adding 22 to
# sshd on a rerun would put two listeners on one port: ssh.socket would fail to
# bind, and because the unit holds both ports its failure takes 1997 -- the only
# way into the host -- down with it.
if remote 'ss -ltnp 2>/dev/null | grep -qE ":${DOOR_SSH_PORT}[[:space:]].*deno" && echo switched || echo not-switched' 2>/dev/null | grep -q switched; then
  echo "port ${DOOR_SSH_PORT} already belongs to this service; leaving sshd on ${HOST_SSHD_PORT}"
else
  remote "${REMOTE_ENV} bash -xe" <<'REMOTE_EOF' || true
install -d -m 755 /etc/systemd/system/ssh.socket.d
cat > /etc/systemd/system/ssh.socket.d/10-port.conf <<SOCKET
[Socket]
ListenStream=
ListenStream=0.0.0.0:${DOOR_SSH_PORT}
ListenStream=[::]:${DOOR_SSH_PORT}
ListenStream=0.0.0.0:${HOST_SSHD_PORT}
ListenStream=[::]:${HOST_SSHD_PORT}
SOCKET
systemctl daemon-reload
systemctl restart ssh.socket
REMOTE_EOF
fi

# ── Prove 1997 answers before giving up 22 ─────────────────────────────────────
# If this fails, nothing has been lost: sshd still holds 22 and the script stops
# while the host is still reachable.
echo "=== verifying sshd answers on ${HOST_SSHD_PORT} ==="
for _ in 1 2 3 4 5 6; do
  if ssh ${SSH_OPTS} -p "$HOST_SSHD_PORT" "$SSH_TARGET" true >/dev/null 2>&1; then
    SSH_ON_HOST_PORT=yes
    break
  fi
  sleep 5
done
if [ "${SSH_ON_HOST_PORT:-}" != "yes" ]; then
  echo "sshd is not answering on ${HOST_SSHD_PORT}; leaving it on ${DOOR_SSH_PORT} and stopping." >&2
  echo "nothing was switched, so the host is reachable exactly as before." >&2
  exit 1
fi
echo "=== 1997 answers; handing 22 to the front door ==="

# ── Phase two, detached ────────────────────────────────────────────────────────
# It runs as a transient unit because it restarts the socket that this session
# depends on. Run inline, the script would die halfway through -- after dropping
# sshd from 22 but before starting anything on it.
remote "cat > /usr/local/sbin/${SERVICE_NAME}-phase2.sh" <<'PHASE2'
#!/usr/bin/env bash
set -xeuo pipefail
exec >/var/log/${SERVICE_NAME}-phase2.log 2>&1

# Arm a rollback before touching the port. Losing it during the switch would
# mean losing the only way into the host, and the way back would be a console.
systemctl stop sshd-port-rollback.timer >/dev/null 2>&1 || true
# The ports are baked into a helper rather than passed through systemd-run:
# nested quoting here silently left ${DOOR_SSH_PORT} unexpanded, which would have
# made the rollback write a malformed socket unit -- a safety net that breaks the
# thing it exists to protect.
cat > /usr/local/sbin/${SERVICE_NAME}-restore-sshd.sh <<RESTORE
#!/usr/bin/env bash
set -xeuo pipefail
printf '[Socket]\nListenStream=\nListenStream=0.0.0.0:${DOOR_SSH_PORT}\nListenStream=[::]:${DOOR_SSH_PORT}\nListenStream=0.0.0.0:${HOST_SSHD_PORT}\nListenStream=[::]:${HOST_SSHD_PORT}\n' > /etc/systemd/system/ssh.socket.d/10-port.conf
systemctl daemon-reload
systemctl restart ssh.socket
RESTORE
chmod +x /usr/local/sbin/${SERVICE_NAME}-restore-sshd.sh
systemd-run --collect --unit=sshd-port-rollback --on-active=5min \
  /usr/local/sbin/${SERVICE_NAME}-restore-sshd.sh

cat > /etc/systemd/system/ssh.socket.d/10-port.conf <<SOCKET
[Socket]
ListenStream=
ListenStream=0.0.0.0:${HOST_SSHD_PORT}
ListenStream=[::]:${HOST_SSHD_PORT}
SOCKET
systemctl daemon-reload
systemctl restart ssh.socket
sleep 2

systemctl restart ${SERVICE_NAME}
sleep 4
systemctl is-active ${SERVICE_NAME} || true
ss -ltn | grep -E ":${DOOR_SSH_PORT} |:${HOST_SSHD_PORT}" || true

# ── Caddy ──────────────────────────────────────────────────────────────────────
# The site is served behind TLS because the page's OAuth client_id must be an
# https URL with no port: off loopback the browser signs in as
# https://<host>/oauth-client-metadata.json, and the authorization server fetches
# that document. Terminating TLS here also means the app speaks plain HTTP.
#
# Written as a drop-in rather than into /etc/caddy/Caddyfile, which
# social-web-computer's own deploy owns and replaces wholesale.
install -d -m 755 /etc/caddy/sites
# The site file used to be named after the service. A leftover under that
# name gives Caddy two blocks for one site and it refuses the whole config
# ("ambiguous site definition").
rm -f /etc/caddy/sites/${SERVICE_NAME}.caddy
cat > /etc/caddy/sites/${ORIGIN}.caddy <<SITE
${ORIGIN} {
  reverse_proxy http://127.0.0.1:8787
}
SITE

if ! grep -qE '^[[:space:]]*import[[:space:]]+/etc/caddy/sites/\*\.caddy' /etc/caddy/Caddyfile; then
  cp /etc/caddy/Caddyfile "/etc/caddy/Caddyfile.bak.$(date +%s)"
  printf '\nimport /etc/caddy/sites/*.caddy\n' >> /etc/caddy/Caddyfile
fi

caddy validate --config /etc/caddy/Caddyfile
systemctl reload caddy || systemctl restart caddy
echo PHASE2_OK
PHASE2

remote "chmod +x /usr/local/sbin/${SERVICE_NAME}-phase2.sh; systemctl stop ${SERVICE_NAME}-phase2.service >/dev/null 2>&1 || true; systemctl reset-failed ${SERVICE_NAME}-phase2.service >/dev/null 2>&1 || true; systemd-run --collect --unit=${SERVICE_NAME}-phase2 ${REMOTE_SETENV} /usr/local/sbin/${SERVICE_NAME}-phase2.sh" || true

# ── Wait for the switch to land ────────────────────────────────────────────────
echo "=== waiting for the front door to take 22 ==="
SWITCHED=no
for _ in $(seq 1 24); do
  if ssh ${SSH_OPTS} -p "$HOST_SSHD_PORT" "$SSH_TARGET" "test \"\$(systemctl is-active ${SERVICE_NAME})\" = active && echo up" 2>/dev/null | grep -q up; then
    SWITCHED=yes
    break
  fi
  sleep 5
done

remote "tail -n 20 /var/log/${SERVICE_NAME}-phase2.log 2>/dev/null || true" || true

if [ "$SWITCHED" != "yes" ]; then
  # The check above can fail for reasons that have nothing to do with the switch
  # (it did once: a quoting bug made every poll miss). Leaving the rollback armed
  # in that case is worse than useless -- it would put sshd back on the port the
  # door is already serving, which is the outage the rollback exists to prevent.
  # So decide on the door itself: if DOOR_SSH_PORT is answering as our server,
  # the switch worked whatever the poll said, and the rollback is disarmed.
  BANNER=$( (exec 3<>/dev/tcp/"${SSH_TARGET#*@}"/"$DOOR_SSH_PORT" 2>/dev/null && head -c 40 <&3) || true)
  case "$BANNER" in
    *ssh2js*)
      echo "the readiness poll missed, but ${DOOR_SSH_PORT} is serving this door; disarming the rollback"
      remote 'systemctl stop sshd-port-rollback.timer >/dev/null 2>&1 || true' || true
      exit 0
      ;;
    *)
      echo "the front door did not come up on ${DOOR_SSH_PORT}; the rollback restores sshd within 5 minutes." >&2
      exit 1
      ;;
  esac
fi

DEPLOY_SSH_PORT=1997
remote 'systemctl stop sshd-port-rollback.timer >/dev/null 2>&1 || true; systemctl reset-failed sshd-port-rollback.service sshd-port-rollback.timer >/dev/null 2>&1 || true; echo "rollback disarmed"'

echo "Deploy complete → https://${ORIGIN}"
echo "SSH door → ssh <your-handle>@${SSH_PUBLIC_HOST}"
echo "Host shell → ssh -p 1997 root@socialweb.computer"

