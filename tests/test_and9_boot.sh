#!/usr/bin/env bash
set -euo pipefail

# PhoneLink AND-9 Android Boot-Persistence & Reboot Recovery Test
# Acceptance Criteria:
# 1. Service resumes after reboot per RECEIVE_BOOT_COMPLETED and deferred-start rules
# 2. Degrades gracefully (prompts user) if OEM auto-start restrictions block it
# 3. Minimum necessary permissions only (no BIND_DEVICE_ADMIN, no persistent flags)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink AND-9 Android Boot-Persistence & Recovery Suite ==="

cd "$REPO_ROOT/android"
./gradlew testDebugUnitTest --tests "com.phonelink.receiver.BootReceiverTest"

echo ""
echo ">>> AND-9 ANDROID BOOT-PERSISTENCE: VERIFIED & PASSED! <<<"
