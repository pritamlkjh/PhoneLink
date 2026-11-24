#!/usr/bin/env bash
set -euo pipefail

# PhoneLink FILE-4 Secure File Upload Integration Test
# Validates E2E encrypted file upload, chunked SHA-256 verification,
# multi-chunk 200KB transfer, resumption from resume_offset, traversal protection,
# sensitive path rejection, tamper detection, and zero plaintext leakage over the VPS relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink FILE-4 Secure File Upload Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestFILE4SecureFileUpload

echo ""
echo ">>> FILE-4 SECURE FILE UPLOAD: VERIFIED & PASSED! <<<"
