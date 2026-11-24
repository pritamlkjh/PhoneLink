import Foundation
import CryptoKit
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

func assertFalse(_ condition: Bool, _ message: String = "", file: String = #file, line: Int = #line) {
    if condition {
        print("FAIL: \(file):\(line) - Condition was true. \(message)")
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

// Test 3: MAC-2 Device Identity Generation and Hex ID Derivation
let tempDir = URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("phonelink_mac_test_\(UUID().uuidString)")
try? FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: tempDir) }

let identity = DeviceIdentityManager(storageDirectory: tempDir)
let devID = identity.deviceID
assertEqual(devID.count, 64, "Device ID must be a 64-character hex string")
assertEqual(identity.deviceID, devID, "Device ID must be deterministic and persistent across calls")
assertEqual(identity.publicKeyBytes.count, 32, "Ed25519 public key must be 32 bytes")
print("PASS: testDeviceIdentityGenerationAndPersistence")

// Test 4: MAC-2 Challenge Signing and Cryptographic Verification
let serverNonce = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32])
let clientNonce = Data([33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64])
let timestamp: Int64 = 1774425000

let signature = try! identity.signChallenge(serverNonce: serverNonce, clientNonce: clientNonce, timestamp: timestamp)
assertEqual(signature.count, 64, "Ed25519 signature must be 64 bytes")

// Build challenge data and verify
var buffer = Data()
buffer.append(serverNonce)
buffer.append(clientNonce)
var bigEndianTimestamp = timestamp.bigEndian
withUnsafeBytes(of: &bigEndianTimestamp) { bytes in
    buffer.append(contentsOf: bytes)
}

let pubKey = try! Curve25519.Signing.PublicKey(rawRepresentation: identity.publicKeyBytes)
assertTrue(pubKey.isValidSignature(signature, for: buffer), "Signature must verify against challenge data")
print("PASS: testChallengeSigningAndVerification")

// Test 5: MAC-2 Tampered Signature Rejection
var corruptedBuffer = buffer
corruptedBuffer[0] ^= 0xFF
assertFalse(pubKey.isValidSignature(signature, for: corruptedBuffer), "Altered nonce must fail signature verification")
print("PASS: testTamperedSignatureRejection")

// Test 6: MAC-2 Credential Wipe / Re-pair Flow
identity.wipeIdentity()
let newIdentity = DeviceIdentityManager(storageDirectory: tempDir)
let newDevID = newIdentity.deviceID
assertFalse(newDevID == devID, "Wiping identity must generate a fresh keypair and distinct device ID")
print("PASS: testWipeAndRePairFlow")

// Test 7: MAC-3 Connection Manager State Representation
let manager = ConnectionManager(
    vpsBaseURL: URL(string: "http://127.0.0.1:8443")!,
    identity: newIdentity
)
assertEqual(manager.state, ConnectionManager.State.disconnected)
assertFalse(manager.state.isConnected)
print("PASS: testConnectionManagerStateRepresentation")

print(">>> ALL MAC CLIENT UNIT TESTS PASSED (7/7) <<<")
exit(0)
