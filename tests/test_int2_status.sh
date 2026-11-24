#!/usr/bin/env bash
set -euo pipefail

# PhoneLink INT-2 Device Discovery & Status Reporting Integration Test
# Validates real-time presence notifications, REST status endpoint,
# and sub-second connect/disconnect latency bounds (< 1000ms).

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink INT-2 Device Discovery & Status Reporting Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestINT2DeviceDiscoveryAndStatusReporting

echo ""
echo ">>> INT-2 DEVICE DISCOVERY & STATUS REPORTING: VERIFIED & PASSED! <<<"
