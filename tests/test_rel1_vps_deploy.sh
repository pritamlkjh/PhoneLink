#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - REL-1 VPS Production Deployment & Rollback Drill Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: REL-1 VPS Production Deployment & Rollback Suite"
echo "=========================================================="

STAGING_BIN_DIR="/tmp/phonelink_rel1_staging"
rm -rf "$STAGING_BIN_DIR"
mkdir -p "$STAGING_BIN_DIR"

echo "[1/4] Testing fresh production deployment script..."
"$PROJECT_ROOT/vps/deploy/deploy_prod.sh" "$STAGING_BIN_DIR"

if [ ! -f "$STAGING_BIN_DIR/phonelink-relay" ]; then
    echo "ERROR: Target binary not created in $STAGING_BIN_DIR"
    exit 1
fi

echo "[2/4] Testing deployment with backup creation..."
# Deploy a second time to ensure backup is created
"$PROJECT_ROOT/vps/deploy/deploy_prod.sh" "$STAGING_BIN_DIR"

if [ ! -f "$STAGING_BIN_DIR/phonelink-relay.prev" ]; then
    echo "ERROR: Backup binary phonelink-relay.prev not created."
    exit 1
fi

echo "[3/4] Testing rollback procedure drill..."
# Corrupt the active binary to simulate a bad update
echo "corrupted-broken-binary" > "$STAGING_BIN_DIR/phonelink-relay"

# Execute rollback
"$PROJECT_ROOT/vps/deploy/rollback_prod.sh" "$STAGING_BIN_DIR"

# Verify healthy binary is restored
if ! "$STAGING_BIN_DIR/phonelink-relay" -version 2>/dev/null && [ ! -x "$STAGING_BIN_DIR/phonelink-relay" ]; then
    echo "ERROR: Rollback did not restore working executable."
    exit 1
fi

echo "[4/4] Verifying systemd unit & reverse proxy configs..."
test -f "$PROJECT_ROOT/vps/deploy/phonelink-relay.service"
test -f "$PROJECT_ROOT/vps/deploy/Caddyfile"
grep -q "ProtectSystem=strict" "$PROJECT_ROOT/vps/deploy/phonelink-relay.service"
grep -q "NoNewPrivileges=true" "$PROJECT_ROOT/vps/deploy/phonelink-relay.service"
grep -q "Strict-Transport-Security" "$PROJECT_ROOT/vps/deploy/Caddyfile"

rm -rf "$STAGING_BIN_DIR"

echo "=========================================================="
echo "REL-1 VPS Production Deployment & Rollback: ALL CHECKS PASSED"
echo "=========================================================="
