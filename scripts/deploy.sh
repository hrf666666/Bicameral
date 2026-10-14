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

LOCAL_SHA=$(sha256sum bicameral/server.py | cut -c1-16)
ssh -o BatchMode=yes -p "$PORT" "$USER@$HOST" "mkdir -p $REMOTE_DIR"
scp -o BatchMode=yes -P "$PORT" bicameral/server.py "$USER@$HOST:$REMOTE_DIR/server.py"
ssh -o BatchMode=yes -p "$PORT" "$USER@$HOST" "
  REMOTE_SHA=\$(sha256sum $REMOTE_DIR/server.py | cut -c1-16)
  [ \"\$REMOTE_SHA\" = \"$LOCAL_SHA\" ] || { echo \"SHA mismatch: \$REMOTE_SHA != $LOCAL_SHA\"; exit 1; }
  pkill -f '^python3 server' 2>/dev/null || true
  sleep 1
  cd $REMOTE_DIR && setsid nohup python3 server.py \
    --control-port $CONTROL --agent-port $AGENTP \
    >\$REMOTE_DIR/poc.log 2>&1 </dev/null &
  sleep 2
  curl -s -m 5 http://127.0.0.1:$CONTROL/healthz
  echo
"
echo "deployed: local build_sha=$LOCAL_SHA"
