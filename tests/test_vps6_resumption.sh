#!/usr/bin/env bash
set -euo pipefail

# PhoneLink VPS-6 VPS Session Resumption & Reconnection Test
# Acceptance Criteria:
# 1. Session resumes after brief disconnect without full re-auth, within a defined token-validity window
# 2. Resumption token accepted only within validity window (expired tokens rejected)
# 3. Resumption token is single-use (replay attacks rejected)
# 4. Revoked devices cannot resume sessions

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink VPS-6 Session Resumption & Reconnection Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./internal/auth -run "TestResumptionToken"
/opt/homebrew/bin/go test -v ./internal/server -run "TestAuthResumeEndpoint"
/opt/homebrew/bin/go test -v ./test/integration -run "^TestVPS6SessionResumptionAndReconnection$"

echo ""
echo ">>> VPS-6 VPS SESSION RESUMPTION: VERIFIED & PASSED! <<<"
