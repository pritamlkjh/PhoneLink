#!/usr/bin/env bash
set -euo pipefail

# PhoneLink INT-3 End-to-End Connection Recovery Test
# Acceptance Criteria:
# 1. System recovers automatically from Android network loss without manual re-pairing
# 2. System recovers automatically from VPS restart without manual re-pairing
# 3. System recovers automatically from Mac network loss without manual re-pairing
# 4. Recovery verified within defined bounds (< 3000ms)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink INT-3 End-to-End Connection Recovery Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run "^TestINT3ConnectionRecoverySuite$"

echo ""
echo ">>> INT-3 END-TO-END CONNECTION RECOVERY: VERIFIED & PASSED! <<<"
