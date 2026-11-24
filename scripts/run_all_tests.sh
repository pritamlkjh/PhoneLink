#!/usr/bin/env bash
# PhoneLink Unified Regression Test Suite Runner
# Runs automated unit and contract tests across all 3 components + shared protocol.
set -eo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "=========================================================="
echo "   PHONELINK UNIFIED REGRESSION TEST SUITE"
echo "=========================================================="
echo "Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "Repo Root: $REPO_ROOT"
echo ""

FAILURES=0

run_step() {
    local name="$1"
    local cmd="$2"
    echo "----------------------------------------------------------"
    echo ">> [STEP] $name"
    echo "----------------------------------------------------------"
    if eval "$cmd"; then
        echo ">> [SUCCESS] $name passed."
    else
        echo ">> [FAILURE] $name FAILED!"
        FAILURES=$((FAILURES + 1))
    fi
    echo ""
}

# 1. Shared Protocol Schemas
run_step "Shared Protobuf Schema Validation & Round-Trip" \
    "$REPO_ROOT/tests/test_schema_roundtrip.sh"

# 2. Secret & Credential Scanning
run_step "Automated Secret & Key Scanning" \
    "$REPO_ROOT/scripts/scan_secrets.sh"

# 3. Mac Client Unit Tests
run_step "Mac Client (Swift) Tests" \
    "cd $REPO_ROOT/mac && swift build && swift run PhoneLinkTests"

# 3. VPS Relay Unit Tests
run_step "VPS Relay (Go) Tests" \
    "cd $REPO_ROOT/vps && /opt/homebrew/bin/go test -v ./..."

# 4. Android Unit Tests
run_step "Android Client (Gradle) Tests" \
    "cd $REPO_ROOT/android && ./gradlew testDebugUnitTest"

# 5. INT-1 End-to-End Relay Integration Tests
run_step "INT-1 End-to-End Encrypted Relay Integration Test" \
    "$REPO_ROOT/tests/test_int1_e2e.sh"

# 6. INT-2 Device Discovery & Status Reporting Integration Tests
run_step "INT-2 Device Discovery & Status Reporting Test" \
    "$REPO_ROOT/tests/test_int2_status.sh"

# 7. FILE-2 Remote File Listing Integration Tests
run_step "FILE-2 Remote File Listing Test" \
    "$REPO_ROOT/tests/test_file2_ls.sh"

# 8. FILE-3 Secure File Download Integration Tests
run_step "FILE-3 Secure File Download Test" \
    "$REPO_ROOT/tests/test_file3_download.sh"

# 9. FILE-4 Secure File Upload Integration Tests
run_step "FILE-4 Secure File Upload Test" \
    "$REPO_ROOT/tests/test_file4_upload.sh"

# 10. FILE-5 Scoped Remote Action System Integration Tests
run_step "FILE-5 Scoped Remote Action System Test" \
    "$REPO_ROOT/tests/test_file5_actions.sh"

# 11. CAM-2 Android Camera Capture Module Integration Tests
run_step "CAM-2 Android Camera Capture Module Test" \
    "$REPO_ROOT/tests/test_cam2_camera.sh"

# 12. CAM-3 Camera Frame Streaming Protocol Integration Tests
run_step "CAM-3 Camera Frame Streaming Protocol Test" \
    "$REPO_ROOT/tests/test_cam3_streaming.sh"

# 13. CAM-4 Mac Camera Viewer Client Integration Tests
run_step "CAM-4 Mac Camera Viewer Client Test" \
    "$REPO_ROOT/tests/test_cam4_viewer.sh"

# 14. SEC-1 Cross-Component Security Hardening Integration Tests
run_step "SEC-1 Cross-Component Security Hardening Test" \
    "$REPO_ROOT/tests/test_sec1_hardening.sh"

# 15. TEST-2 Cross-Component Integration Test Suite
run_step "TEST-2 Cross-Component Integration Suite (2x & Regression Check)" \
    "$REPO_ROOT/tests/test_test2_cross_component.sh"

# 16. VPS-7 VPS Logging & Monitoring Integration Tests
run_step "VPS-7 VPS Logging & Monitoring Test" \
    "$REPO_ROOT/tests/test_vps7_logging.sh"

# 17. SEC-2 Security Validation & Penetration Testing Suite
run_step "SEC-2 Security Validation & Penetration Testing Suite" \
    "$REPO_ROOT/tests/test_sec2_pentest.sh"

# 18. VPS-6 VPS Session Resumption & Reconnection
run_step "VPS-6 VPS Session Resumption & Reconnection" \
    "$REPO_ROOT/tests/test_vps6_resumption.sh"

# 19. AND-8 Android Reconnection & Network-Change Handling
run_step "AND-8 Android Reconnection & Network-Change Handling" \
    "$REPO_ROOT/tests/test_and8_reconnection.sh"

# 20. INT-3 End-to-End Connection Recovery
run_step "INT-3 End-to-End Connection Recovery" \
    "$REPO_ROOT/tests/test_int3_recovery.sh"

# 21. AND-9 Android Boot-Persistence & Reboot Recovery
run_step "AND-9 Android Boot-Persistence & Reboot Recovery" \
    "$REPO_ROOT/tests/test_and9_boot.sh"

# 22. TEST-3 Network Failure & Chaos Testing
run_step "TEST-3 Network Failure & Chaos Testing" \
    "$REPO_ROOT/tests/test_test3_chaos.sh"

# 23. TEST-4 Android Compatibility Matrix Testing
run_step "TEST-4 Android Compatibility Matrix Testing" \
    "$REPO_ROOT/tests/test_test4_compatibility.sh"

# 24. REL-1 VPS Production Deployment & Rollback
run_step "REL-1 VPS Production Deployment & Rollback" \
    "$REPO_ROOT/tests/test_rel1_vps_deploy.sh"

# 25. REL-2 Android Release Build & Signing
run_step "REL-2 Android Release Build & Signing" \
    "$REPO_ROOT/tests/test_rel2_android_release.sh"

# 26. REL-3 Mac Release Build & Packaging
run_step "REL-3 Mac Release Build & Packaging" \
    "$REPO_ROOT/tests/test_rel3_mac_release.sh"

# 27. DOC-1 Consolidated Documentation & Setup Guide
run_step "DOC-1 Consolidated Documentation & Setup Guide" \
    "$REPO_ROOT/tests/test_doc1_docs.sh"

# 28. VPS-8 VPS Direct-Connection Optimization
run_step "VPS-8 VPS Direct-Connection Optimization" \
    "$REPO_ROOT/tests/test_vps8_direct.sh"

echo "=========================================================="
if [ $FAILURES -eq 0 ]; then
    echo "   ALL REGRESSION SUITES PASSED (28/28)"
    echo "=========================================================="
    exit 0
else
    echo "   SUITE FAILED WITH $FAILURES FAILURE(S)"
    echo "=========================================================="
    exit 1
fi
