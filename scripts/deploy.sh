#!/usr/bin/env bash
# Deploy bicameral/server.py to a host, restart, and verify the running
# fingerprint matches the local file (build_sha check kills version drift).
# Usage: HOST=10.70.251.39 PORT=31451 USER=root ./scripts/deploy.sh
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
  LOCAL_SHA="$LOCAL_SHA" REMOTE_DIR="$REMOTE_DIR" CONTROL="$CONTROL" AGENTP="$AGENTP" 'bash -s' <<'REMOTE'
set -euo pipefail
. "$REMOTE_DIR/.server_args"
REMOTE_SHA=$(sha256sum "$REMOTE_DIR/server.py" | cut -c1-16)
[ "$REMOTE_SHA" = "$LOCAL_SHA" ] || { echo "SHA mismatch: $REMOTE_SHA != $LOCAL_SHA"; exit 1; }
# match both launch forms: "python3 server.py" (cwd-launched) and the full path
pkill -f "python3 ($REMOTE_DIR/)?server\.py" 2>/dev/null || true
sleep 1
cd "$REMOTE_DIR"
BICAMERAL_ADMIN_TOKEN=$(cat "$REMOTE_DIR/.admin_token") setsid nohup python3 server.py \
  --control-port "$CONTROL" --agent-port "$AGENTP" $SERVER_ARGS \
  >"$REMOTE_DIR/poc.log" 2>&1 </dev/null &
sleep 2
HEALTH=$(curl -s -m 5 "http://127.0.0.1:$CONTROL/healthz")
echo "$HEALTH"
echo "$HEALTH" | grep -q "$LOCAL_SHA" || {
  echo "FINGERPRINT MISMATCH: running instance is not this build"; exit 1; }
REMOTE
echo "deployed: local build_sha=$LOCAL_SHA"
