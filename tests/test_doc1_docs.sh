#!/usr/bin/env bash
set -euo pipefail

# PhoneLink - DOC-1 Consolidated Documentation Dogfood & Verification Runner
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "PhoneLink: DOC-1 Consolidated Documentation Suite"
echo "=========================================================="

echo "[1/4] Verifying presence of core documentation artifacts..."
test -f "$PROJECT_ROOT/README.md"
test -f "$PROJECT_ROOT/docs/SETUP_GUIDE.md"
test -f "$PROJECT_ROOT/docs/PRIVACY_MODEL.md"
test -f "$PROJECT_ROOT/docs/USER_MANUAL.md"
test -f "$PROJECT_ROOT/docs/VPS_PRODUCTION_DEPLOYMENT.md"

echo "[2/4] Verifying documentation markdown cross-references..."
cd "$PROJECT_ROOT"
# Extract and verify all markdown relative links formatted like (docs/...) or (README.md)
grep -oE '\(docs/[^)]+\.md\)' README.md | tr -d '()' | while read -r link; do
    if [ ! -f "$PROJECT_ROOT/$link" ]; then
        echo "ERROR: Broken documentation link in README.md -> $link"
        exit 1
    fi
    echo "  -> Verified link: $link"
done

echo "[3/4] Validating privacy & anti-stalkerware statement invariants..."
grep -q "Anti-Stalkerware Guarantees" "$PROJECT_ROOT/docs/PRIVACY_MODEL.md"
grep -q "Permanent, Un-dismissible Foreground Notification" "$PROJECT_ROOT/docs/PRIVACY_MODEL.md"
grep -q "Dual-Gate Camera Activation" "$PROJECT_ROOT/docs/PRIVACY_MODEL.md"
grep -q "Zero-Plaintext Guarantee" "$PROJECT_ROOT/docs/PRIVACY_MODEL.md"

echo "[4/4] Verifying setup instructions and CLI syntax consistency..."
grep -q "phonelink pair" "$PROJECT_ROOT/docs/SETUP_GUIDE.md"
grep -q "phonelink files list" "$PROJECT_ROOT/docs/USER_MANUAL.md"
grep -q "phonelink actions locate" "$PROJECT_ROOT/docs/USER_MANUAL.md"
grep -q "phonelink camera preview" "$PROJECT_ROOT/docs/USER_MANUAL.md"

echo "=========================================================="
echo "DOC-1 Consolidated Documentation: ALL CHECKS PASSED"
echo "=========================================================="
