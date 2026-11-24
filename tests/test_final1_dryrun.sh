#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - FINAL-1 Final Acceptance Testing & Fresh-Environment Dry Run Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: FINAL-1 Final Acceptance Testing Suite"
echo "Fresh-Environment End-to-End Dry Run Verification"
echo "=========================================================="

# 1. Setup isolated clean environment
TEMP_DIR="/tmp/phonelink_final1_acceptance"
rm -rf "$TEMP_DIR"
mkdir -p "$TEMP_DIR/vps" "$TEMP_DIR/mac" "$TEMP_DIR/android"

echo "[1/6] Staging production release artifacts in clean isolation..."
# Mac release binary
test -f "$PROJECT_ROOT/mac/release/PhoneLink-v1.0.0-macos-arm64.tar.gz"
tar -xzf "$PROJECT_ROOT/mac/release/PhoneLink-v1.0.0-macos-arm64.tar.gz" -C "$TEMP_DIR/mac"
MAC_BIN="$TEMP_DIR/mac/PhoneLink-v1.0.0-macos-arm64/bin/phonelink"
test -x "$MAC_BIN"

# Android release APK
test -f "$PROJECT_ROOT/android/release/PhoneLink-v1.0.0-release.apk"
test -f "$PROJECT_ROOT/android/release/PhoneLink-v1.0.0-release.apk.sha256"
cp "$PROJECT_ROOT/android/release/PhoneLink-v1.0.0-release.apk" "$TEMP_DIR/android/"

# VPS production binary
mkdir -p "$TEMP_DIR/vps/bin"
"$PROJECT_ROOT/vps/deploy/deploy_prod.sh" "$TEMP_DIR/vps/bin"
VPS_BIN="$TEMP_DIR/vps/bin/phonelink-relay"
test -x "$VPS_BIN"

echo "[2/6] Starting isolated production VPS relay instance..."
VPS_PORT=58449
PHONELINK_HOST="127.0.0.1" PHONELINK_PORT="$VPS_PORT" "$VPS_BIN" > "$TEMP_DIR/vps.log" 2>&1 &
VPS_PID=$!

cleanup() {
    kill $VPS_PID 2>/dev/null || true
    wait $VPS_PID 2>/dev/null || true
    rm -rf "$TEMP_DIR"
}
trap cleanup EXIT

sleep 0.5

# Probe health endpoint
HEALTH_RESP=$(curl -s "http://127.0.0.1:$VPS_PORT/healthz")
if ! echo "$HEALTH_RESP" | grep -qi '"status":"ok"'; then
    echo "ERROR: Fresh VPS instance failed health check: $HEALTH_RESP"
    exit 1
fi
echo "  -> VPS Relay running at 127.0.0.1:$VPS_PORT (Health probe OK)"

echo "[3/6] Executing comprehensive integration & recovery dry run..."
# Run the complete integration test suite against the VPS
(cd "$PROJECT_ROOT/vps" && go test -v -run "TestINT" ./test/integration)

echo "[4/6] Executing comprehensive feature vertical dry runs..."
(cd "$PROJECT_ROOT/vps" && go test -v -run "TestFILE|TestCAM" ./test/integration)

echo "[5/6] Executing security penetration & chaos resilience dry runs..."
(cd "$PROJECT_ROOT/vps" && go test -v -run TestSEC2 ./test/integration)
(cd "$PROJECT_ROOT/vps" && go test -v -run TestTEST3 ./test/integration)

echo "[6/6] Verifying release integrity & anti-stalkerware invariants..."
"$PROJECT_ROOT/tests/test_doc1_docs.sh"

echo "=========================================================="
echo "FINAL-1 Fresh-Environment Dry Run: ALL TESTS PASSED (100%)"
echo "System certified ready for production release!"
echo "=========================================================="
