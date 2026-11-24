import Foundation
import PhoneLinkKit

func assertEqual<T: Equatable>(_ actual: T, _ expected: T, _ message: String = "", file: String = #file, line: Int = #line) {
    if actual != expected {
        print("FAIL: \(file):\(line) - Expected '\(expected)' but got '\(actual)'. \(message)")
        exit(1)
    }
}

func assertTrue(_ condition: Bool, _ message: String = "", file: String = #file, line: Int = #line) {
    if !condition {
        print("FAIL: \(file):\(line) - Condition was false. \(message)")
        exit(1)
    }
}

print("=== Running PhoneLink Mac Unit Tests ===")

// Test 1: Version and Banner
assertEqual(PhoneLinkInfo.version, "1.0.0", "Version should be 1.0.0")
assertTrue(PhoneLinkInfo.banner().contains("PhoneLink Mac Client"), "Banner should contain client name")
assertTrue(PhoneLinkInfo.banner().contains("1.0.0"), "Banner should contain version")
print("PASS: testVersionAndBanner")

// Test 2: Connection States
assertEqual(ConnectionState.disconnected.rawValue, "disconnected")
assertEqual(ConnectionState.connecting.rawValue, "connecting")
assertEqual(ConnectionState.authenticated.rawValue, "authenticated")
assertEqual(ConnectionState.peerConnected.rawValue, "peerConnected")
assertEqual(ConnectionState.error.rawValue, "error")
print("PASS: testConnectionStates")

print(">>> ALL MAC CLIENT UNIT TESTS PASSED (2/2) <<<")
exit(0)
