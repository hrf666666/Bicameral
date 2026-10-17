#!/usr/bin/env bash
# Deploy bicameral/server.py to a host, restart, and verify the running
# fingerprint matches the local file (build_sha check kills version drift).
# Usage: HOST=10.70.251.39 PORT=31451 USER=root ./scripts/deploy.sh
# Optional TLS data plane (certs: see deploy/tls/README.md):
#   TLS_CERT=deploy/tls/server.crt TLS_KEY=deploy/tls/server.key ./scripts/deploy.sh
#     -> both planes serve TLS (--tls-cert/--tls-key).
#   + TLS_CLIENT_CA=deploy/tls/ca.crt         -> require client certs (mTLS)
#   + TLS_CLIENT_CERT/TLS_CLIENT_KEY          -> client cert for the post-deploy
#                                                health check (mTLS only)
# Without TLS_CERT/TLS_KEY the deploy is plain HTTP exactly as before.
set -euo pipefail
HOST="${HOST:?set HOST}"
PORT="${PORT:-22}"
USER="${USER:-root}"
REMOTE_DIR="${REMOTE_DIR:-/root/bicameral}"
CONTROL="${CONTROL:-18000}"
AGENTP="${AGENTP:-18001}"
SERVER_ARGS="${SERVER_ARGS:-}"                  # extra server flags (space-separated)
[ "${NO_THINK:-0}" = "1" ] && SERVER_ARGS="$SERVER_ARGS --no-think"
[ -n "${LLM_MAX_TOKENS:-}" ] && SERVER_ARGS="$SERVER_ARGS --llm-max-tokens $LLM_MAX_TOKENS"

# --- optional TLS data plane (off by default: no cert vars = plain HTTP) --- #
TLS_CERT="${TLS_CERT:-}"
TLS_KEY="${TLS_KEY:-}"
TLS_CLIENT_CA="${TLS_CLIENT_CA:-}"
TLS_CLIENT_CERT="${TLS_CLIENT_CERT:-}"
TLS_CLIENT_KEY="${TLS_CLIENT_KEY:-}"
HEALTH_URL="http://127.0.0.1:$CONTROL/healthz"  # what the post-deploy check hits
CURL_TLS=""                                     # extra curl flags for that check
if [ -n "$TLS_CERT" ] || [ -n "$TLS_KEY" ]; then
  if [ -z "$TLS_CERT" ] || [ -z "$TLS_KEY" ]; then
    echo "deploy: TLS_CERT and TLS_KEY must be given together" >&2; exit 1
  fi
  for f in "$TLS_CERT" "$TLS_KEY"; do
    [ -f "$f" ] || { echo "deploy: TLS file not found: $f" >&2; exit 1; }
  done
  scp -o BatchMode=yes -P "$PORT" "$TLS_CERT" "$USER@$HOST:$REMOTE_DIR/tls-cert.pem"
  scp -o BatchMode=yes -P "$PORT" "$TLS_KEY" "$USER@$HOST:$REMOTE_DIR/tls-key.pem"
  SERVER_ARGS="$SERVER_ARGS --tls-cert $REMOTE_DIR/tls-cert.pem --tls-key $REMOTE_DIR/tls-key.pem"
  HEALTH_URL="https://127.0.0.1:$CONTROL/healthz"
  CURL_TLS="-k"
  echo "deploy: TLS enabled (server cert+key uploaded; both planes serve TLS)"
  if [ -n "$TLS_CLIENT_CA" ]; then
    [ -f "$TLS_CLIENT_CA" ] || { echo "deploy: TLS client CA not found: $TLS_CLIENT_CA" >&2; exit 1; }
    scp -o BatchMode=yes -P "$PORT" "$TLS_CLIENT_CA" "$USER@$HOST:$REMOTE_DIR/tls-client-ca.pem"
    SERVER_ARGS="$SERVER_ARGS --tls-client-ca $REMOTE_DIR/tls-client-ca.pem"
    echo "deploy: mTLS enabled (client certificates required)"
    if [ -n "$TLS_CLIENT_CERT" ] || [ -n "$TLS_CLIENT_KEY" ]; then
      if [ -z "$TLS_CLIENT_CERT" ] || [ -z "$TLS_CLIENT_KEY" ]; then
        echo "deploy: TLS_CLIENT_CERT and TLS_CLIENT_KEY must be given together" >&2; exit 1
      fi
      for f in "$TLS_CLIENT_CERT" "$TLS_CLIENT_KEY"; do
        [ -f "$f" ] || { echo "deploy: TLS client file not found: $f" >&2; exit 1; }
      done
      scp -o BatchMode=yes -P "$PORT" "$TLS_CLIENT_CERT" "$USER@$HOST:$REMOTE_DIR/tls-client.pem"
      scp -o BatchMode=yes -P "$PORT" "$TLS_CLIENT_KEY" "$USER@$HOST:$REMOTE_DIR/tls-client-key.pem"
      CURL_TLS="$CURL_TLS --cert $REMOTE_DIR/tls-client.pem --key $REMOTE_DIR/tls-client-key.pem"
    else
      echo "deploy: WARNING: mTLS is on but TLS_CLIENT_CERT/TLS_CLIENT_KEY are not set —" \
           "the post-deploy health check below will fail the TLS handshake" >&2
    fi
  fi
else
  echo "deploy: TLS_CERT/TLS_KEY not set — deploying plain HTTP (TLS disabled)"
fi

ADMIN_TOKEN="${ADMIN_TOKEN:?set ADMIN_TOKEN (control-plane token, >=16 chars)}"
LOCAL_SHA=$(sha256sum bicameral/server.py | cut -c1-16)
ssh -o BatchMode=yes -p "$PORT" "$USER@$HOST" "mkdir -p $REMOTE_DIR"
scp -o BatchMode=yes -P "$PORT" bicameral/server.py "$USER@$HOST:$REMOTE_DIR/server.py"
# remote script via stdin (quoted heredoc: nothing expands locally; the remote
# shell's argv is just "bash -s", so the pkill pattern can never match it)
printf '%s' "$ADMIN_TOKEN" | ssh -o BatchMode=yes -p "$PORT" "$USER@$HOST" \
  "umask 077; mkdir -p $REMOTE_DIR; cat > $REMOTE_DIR/.admin_token"
# SERVER_ARGS may contain spaces: ship via a 0600 env file (ssh argv flattens
# quotes into "line 1: --no-think: command not found")
printf 'SERVER_ARGS=%q\n' "$SERVER_ARGS" | ssh -o BatchMode=yes -p "$PORT" "$USER@$HOST" \
  "umask 077; cat > $REMOTE_DIR/.server_args"
ssh -o BatchMode=yes -p "$PORT" "$USER@$HOST" \
  LOCAL_SHA="$LOCAL_SHA" REMOTE_DIR="$REMOTE_DIR" CONTROL="$CONTROL" AGENTP="$AGENTP" \
  HEALTH_URL="$HEALTH_URL" CURL_TLS="$CURL_TLS" 'bash -s' <<'REMOTE'
set -euo pipefail
. "$REMOTE_DIR/.server_args"
REMOTE_SHA=$(sha256sum "$REMOTE_DIR/server.py" | cut -c1-16)
[ "$REMOTE_SHA" = "$LOCAL_SHA" ] || { echo "SHA mismatch: $REMOTE_SHA != $LOCAL_SHA"; exit 1; }
chmod 600 "$REMOTE_DIR"/tls-*.pem 2>/dev/null || true
# match both launch forms: "python3 server.py" (cwd-launched) and the full path
pkill -f "python3 ($REMOTE_DIR/)?server\.py" 2>/dev/null || true
sleep 1
cd "$REMOTE_DIR"
BICAMERAL_ADMIN_TOKEN=$(cat "$REMOTE_DIR/.admin_token") setsid nohup python3 server.py \
  --control-port "$CONTROL" --agent-port "$AGENTP" $SERVER_ARGS \
  >"$REMOTE_DIR/poc.log" 2>&1 </dev/null &
sleep 2
HEALTH=$(curl $CURL_TLS -s -m 5 "$HEALTH_URL")
echo "$HEALTH"
echo "$HEALTH" | grep -q "$LOCAL_SHA" || {
  echo "FINGERPRINT MISMATCH: running instance is not this build"; exit 1; }
REMOTE
echo "deployed: local build_sha=$LOCAL_SHA"
