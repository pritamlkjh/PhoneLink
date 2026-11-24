#!/usr/bin/env bash
set -euo pipefail

# PhoneLink FILE-5 Scoped Remote Action System Integration Test
# Validates E2E encrypted scoped remote action execution (device.ping, device.info),
# duration clamping, permission gating, arbitrary command rejection, and zero plaintext leakage.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink FILE-5 Scoped Remote Action System Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestFILE5ScopedRemoteActions

echo ""
echo ">>> FILE-5 SCOPED REMOTE ACTION SYSTEM: VERIFIED & PASSED! <<<"
