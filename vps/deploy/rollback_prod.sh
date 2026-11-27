#!/usr/bin/env bash
# PhoneLink Production VPS Relay Rollback Script
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VPS_DIR="$(dirname "$SCRIPT_DIR")"
TARGET_BIN_DIR="${1:-$VPS_DIR/bin}"
TARGET_BIN="$TARGET_BIN_DIR/phonelink-relay"
BACKUP_BIN="$TARGET_BIN_DIR/phonelink-relay.prev"

echo "=========================================================="
echo "PhoneLink: Production VPS Relay Rollback"
echo "=========================================================="

if [ ! -f "$BACKUP_BIN" ]; then
    echo "ERROR: No backup binary found at $BACKUP_BIN. Cannot perform rollback."
    exit 1
fi

echo "[1/2] Restoring previous binary from backup..."
cp "$TARGET_BIN" "$TARGET_BIN_DIR/phonelink-relay.failed" 2>/dev/null || true
mv "$BACKUP_BIN" "$TARGET_BIN"
echo "  -> Restored $BACKUP_BIN -> $TARGET_BIN"

echo "[2/2] Verifying rolled-back binary health..."
TEST_PORT=58444
ROLLBACK_TEST_LOG=$(mktemp -t phonelink_rollback_test.XXXXXX)
trap 'rm -f "$ROLLBACK_TEST_LOG"' EXIT
PHONELINK_HOST="127.0.0.1" PHONELINK_PORT="$TEST_PORT" "$TARGET_BIN" > "$ROLLBACK_TEST_LOG" 2>&1 &
SERVER_PID=$!

sleep 0.5

HEALTH_STATUS=$(curl -s "http://127.0.0.1:$TEST_PORT/healthz" || true)
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true

if echo "$HEALTH_STATUS" | grep -qi '"status":"ok"'; then
    echo "  -> Rolled-back health probe OK: $HEALTH_STATUS"
    echo "=========================================================="
    echo "SUCCESS: Rollback procedure completed and verified!"
    echo "=========================================================="
    exit 0
else
    echo "FATAL: Rolled-back binary failed health probe: $HEALTH_STATUS"
    exit 1
fi
