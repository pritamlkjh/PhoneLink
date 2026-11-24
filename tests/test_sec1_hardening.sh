#!/usr/bin/env bash
set -euo pipefail

# PhoneLink SEC-1 Cross-Component Security Hardening Integration Test
# Validates replay protection, clock-skew freshness enforcement, fuzzing tolerance,
# certificate pinning validation, and zero plaintext leakage across the VPS relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink SEC-1 Security Hardening Integration Suite ==="

cd "$REPO_ROOT/vps"
/opt/homebrew/bin/go test -v ./test/integration -run TestSEC1CrossComponentSecurityHardening

echo ""
echo ">>> SEC-1 CROSS-COMPONENT SECURITY HARDENING: VERIFIED & PASSED! <<<"
