#!/usr/bin/env bash
set -euo pipefail

# PhoneLink CAM-2 Android Camera Capture Module Integration Test
# Validates dual-gate authorization enforcement (CAM-1 invariant), foreground service
# camera elevation, frame streaming over E2E encrypted relay, immediate deactivation,
# watchdog timeout deactivation, and zero plaintext leakage over the VPS relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink CAM-2 Android Camera Capture Module Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestCAM2AndroidCameraCaptureModule

echo ""
echo ">>> CAM-2 ANDROID CAMERA CAPTURE MODULE: VERIFIED & PASSED! <<<"
