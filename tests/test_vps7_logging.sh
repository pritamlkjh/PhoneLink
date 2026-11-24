#!/usr/bin/env bash
set -euo pipefail

# PhoneLink VPS-7 VPS Logging & Monitoring Integration Test
# Acceptance Criteria:
# 1. Structured logs for auth/connection/error events
# 2. File contents, camera frames, and message payloads never logged
# 3. Basic alerting on repeated auth failures

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink VPS-7 Logging & Monitoring Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run "^TestVPS7LoggingAndMonitoring$"

echo ""
echo ">>> VPS-7 VPS LOGGING & MONITORING: VERIFIED & PASSED! <<<"
