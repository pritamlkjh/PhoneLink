#!/usr/bin/env bash
set -euo pipefail

# PhoneLink AND-8 Android Reconnection & Network-Change Handling Test
# Acceptance Criteria:
# 1. Detects connectivity loss and Wi-Fi/cellular handoff
# 2. Reconnects with exponential backoff and jitter (no reconnect storms)
# 3. Resumes session without full re-auth where protocol allows (VPS-6 coordination)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink AND-8 Android Reconnection & Network-Change Suite ==="

cd "$REPO_ROOT/android"
./gradlew testDebugUnitTest --tests "com.phonelink.transport.ReconnectionManagerTest"

echo ""
echo ">>> AND-8 ANDROID RECONNECTION: VERIFIED & PASSED! <<<"
