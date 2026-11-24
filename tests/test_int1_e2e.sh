#!/usr/bin/env bash
set -euo pipefail

# PhoneLink INT-1 End-to-End Encrypted Connection Integration Test
# Validates real device identity generation, VPS authentication, pairing,
# WebSocket connection, ephemeral X25519 key exchange, and AES-256-GCM ciphertext relay.
# Also verifies zero plaintext leakage on the VPS relay.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=== Running PhoneLink INT-1 End-to-End Encrypted Relay Suite ==="

cd "$REPO_ROOT/vps"
go test -v ./test/integration -run TestINT1FirstEndToEndEncryptedConnection

echo ""
echo ">>> INT-1 FIRST END-TO-END ENCRYPTED CONNECTION: VERIFIED & PASSED! <<<"
