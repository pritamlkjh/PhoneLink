#!/usr/bin/env bash
# PhoneLink Production VPS Relay Deployment Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPS_DIR="$(dirname "$SCRIPT_DIR")"
TARGET_BIN_DIR="${1:-$VPS_DIR/bin}"
TARGET_BIN="$TARGET_BIN_DIR/phonelink-relay"
BACKUP_BIN="$TARGET_BIN_DIR/phonelink-relay.prev"
NEW_BIN="$TARGET_BIN_DIR/phonelink-relay.new"

echo "=========================================================="
echo "PhoneLink: Production VPS Relay Deployment"
echo "=========================================================="
echo "Source: $VPS_DIR"
echo "Target Binary: $TARGET_BIN"

# 1. Pre-flight Verification
echo "[1/4] Running pre-flight unit test verification..."
(cd "$VPS_DIR" && go test ./internal/...)

# 2. Build hardened production binary
echo "[2/4] Compiling stripped production binary..."
mkdir -p "$TARGET_BIN_DIR"
(cd "$VPS_DIR" && CGO_ENABLED=0 go build -ldflags="-w -s" -o "$NEW_BIN" ./cmd/relay)

if [ ! -f "$NEW_BIN" ]; then
    echo "ERROR: Production binary build failed."
    exit 1
fi

chmod +x "$NEW_BIN"

# 3. Atomic Binary Swap with Backup
echo "[3/4] Performing atomic binary swap..."
if [ -f "$TARGET_BIN" ]; then
    cp "$TARGET_BIN" "$BACKUP_BIN"
    echo "  -> Saved backup to $BACKUP_BIN"
fi

mv "$NEW_BIN" "$TARGET_BIN"
echo "  -> Installed new binary at $TARGET_BIN"

# 4. Production Smoke / Health Check Verification
echo "[4/4] Verifying binary execution & health check..."
TEST_PORT=58443
PROD_TEST_LOG=$(mktemp -t phonelink_prod_test.XXXXXX)
trap 'rm -f "$PROD_TEST_LOG"' EXIT
PHONELINK_HOST="127.0.0.1" PHONELINK_PORT="$TEST_PORT" "$TARGET_BIN" > "$PROD_TEST_LOG" 2>&1 &
SERVER_PID=$!

sleep 0.5

HEALTH_STATUS=$(curl -s "http://127.0.0.1:$TEST_PORT/healthz" || true)
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

if echo "$HEALTH_STATUS" | grep -qi '"status":"ok"'; then
    echo "  -> Health probe OK: $HEALTH_STATUS"
    echo "=========================================================="
    echo "SUCCESS: Production VPS deployment completed and verified!"
    echo "=========================================================="
    exit 0
else
    echo "ERROR: Production health probe failed. Received: $HEALTH_STATUS"
    echo "Initiating automatic rollback..."
    if [ -f "$BACKUP_BIN" ]; then
        mv "$BACKUP_BIN" "$TARGET_BIN"
        echo "Automatic rollback completed: restored $BACKUP_BIN -> $TARGET_BIN"
    fi
    exit 1
fi
