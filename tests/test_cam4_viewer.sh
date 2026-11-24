#!/usr/bin/env bash
set -euo pipefail

# PhoneLink CAM-4 Mac Camera Viewer Client Integration Test
# Validates live frame rendering in viewer, active state presentation, stale frame
# watchdog detection, and clear inactive state display upon camera deactivation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink CAM-4 Mac Camera Viewer Client Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestCAM4MacCameraViewerClient

echo ""
echo ">>> CAM-4 MAC CAMERA VIEWER CLIENT: VERIFIED & PASSED! <<<"
