#!/usr/bin/env bash
set -euo pipefail

# PhoneLink FILE-3 Secure File Download Integration Test
# Validates E2E encrypted file download, chunked SHA-256 verification,
# large-file transfer, resumption on interruption, traversal protection,
# tamper detection, and zero plaintext leakage over the VPS relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink FILE-3 Secure File Download Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestFILE3SecureFileDownload

echo ""
echo ">>> FILE-3 SECURE FILE DOWNLOAD: VERIFIED & PASSED! <<<"
