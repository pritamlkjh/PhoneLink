#!/usr/bin/env bash
set -euo pipefail

# PhoneLink TEST-2 Cross-Component Integration Test Suite
# Acceptance Criteria:
# 1. Scripted suite exercises auth, discovery, files, remote actions, and camera against staging VPS.
# 2. Full suite passes twice consecutively (flakiness verification).
# 3. Suite fails clearly on an intentionally introduced regression.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================================="
echo "=== PhoneLink TEST-2 Cross-Component Integration Suite ==="
echo "=========================================================="

cd "$REPO_ROOT/vps"

echo ">> [RUN 1/2] Executing Full Cross-Component Integration Suite..."
/opt/homebrew/bin/go test -v ./test/integration -run "^TestTEST2CrossComponentIntegrationSuite$" -count=1
echo ">> [RUN 1/2] PASS: First execution succeeded."
echo ""

echo ">> [RUN 2/2] Executing Full Suite 2nd Time (Flakiness Verification)..."
/opt/homebrew/bin/go test -v ./test/integration -run "^TestTEST2CrossComponentIntegrationSuite$" -count=1
echo ">> [RUN 2/2] PASS: Second execution succeeded with 0 flakiness."
echo ""

echo ">> [REGRESSION CHECK] Verifying clear failure on intentionally introduced regression..."
/opt/homebrew/bin/go test -v ./test/integration -run "^TestTEST2IntentionalRegressionFailure$" -count=1
echo ">> [REGRESSION CHECK] PASS: Regression caught cleanly."

echo ""
echo ">>> TEST-2 CROSS-COMPONENT INTEGRATION SUITE: 100% VERIFIED & PASSED! <<<"
