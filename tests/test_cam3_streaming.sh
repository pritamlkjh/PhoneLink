#!/usr/bin/env bash
set -euo pipefail

# PhoneLink CAM-3 Camera Frame Streaming Protocol & Transport Integration Test
# Validates end-to-end encrypted preview streaming over VPS-4 relay, rate pacing (1..5 FPS),
# latency measurement, backpressure gap detection, prompt stream cessation after deactivation,
# and zero plaintext leakage over the relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink CAM-3 Camera Frame Streaming Protocol Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestCAM3CameraFrameStreamingProtocol

echo ""
echo ">>> CAM-3 CAMERA FRAME STREAMING PROTOCOL: VERIFIED & PASSED! <<<"
