#!/usr/bin/env bash
set -euo pipefail

# PhoneLink FILE-2 Remote File Listing Integration Test
# Validates E2E encrypted directory listing, traversal protection,
# path filtering, and zero plaintext leakage over the VPS relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink FILE-2 Remote File Listing Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestFILE2RemoteFileListing

echo ""
echo ">>> FILE-2 REMOTE FILE LISTING: VERIFIED & PASSED! <<<"
