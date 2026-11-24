import Foundation
import CryptoKit
import Security

/// MAC-2: Mac Authentication & Identity
/// Manages Ed25519 device identity keypair, Keychain storage, challenge signing, and wipe/re-pair.
public final class DeviceIdentityManager: @unchecked Sendable {
    public static let shared = DeviceIdentityManager()

    private let keychainService = "com.phonelink.mac.identity"
    private let keychainAccount = "device_identity_key"
    private let fallbackFilePath: URL

    private var cachedPrivateKey: Curve25519.Signing.PrivateKey?
    private let lock = NSLock()

    public init(storageDirectory: URL? = nil) {
        let baseDir = storageDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first ?? URL(fileURLWithPath: NSTemporaryDirectory())
        self.fallbackFilePath = baseDir.appendingPathComponent("phonelink_identity.key")
    }

    /// Retrieves existing identity private key or generates a fresh one.
    public func getOrCreatePrivateKey() -> Curve25519.Signing.PrivateKey {
        lock.lock()
        defer { lock.unlock() }

        if let cached = cachedPrivateKey {
            return cached
        }

        // 1. Try Keychain
        if let keyData = readFromKeychain() {
            if let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: keyData) {
                cachedPrivateKey = key
                return key
            }
        }

        // 2. Try Fallback file
        if let keyData = try? Data(contentsOf: fallbackFilePath) {
            if let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: keyData) {
                cachedPrivateKey = key
                return key
            }
        }

        // 3. Generate fresh keypair
        let newKey = Curve25519.Signing.PrivateKey()
        saveToKeychain(data: newKey.rawRepresentation)
        try? newKey.rawRepresentation.write(to: fallbackFilePath, options: .atomic)

        cachedPrivateKey = newKey
        return newKey
    }

    /// Stable 64-character hex device ID derived from HEX(SHA-256(publicKey)).
    public var deviceID: String {
        let pubKeyData = getOrCreatePrivateKey().publicKey.rawRepresentation
        let digest = SHA256.hash(data: pubKeyData)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Ed25519 raw public key bytes.
    public var publicKeyBytes: Data {
        return getOrCreatePrivateKey().publicKey.rawRepresentation
    }

    /// Base64 encoded public key string.
    public var publicKeyBase64: String {
        return publicKeyBytes.base64EncodedString()
    }

    /// Signs an authentication challenge: (serverNonce || clientNonce || 8-byte big-endian timestamp).
    public func signChallenge(serverNonce: Data, clientNonce: Data, timestamp: Int64) throws -> Data {
        let privKey = getOrCreatePrivateKey()
        var buffer = Data()
        buffer.append(serverNonce)
        buffer.append(clientNonce)

        var bigEndianTimestamp = timestamp.bigEndian
        withUnsafeBytes(of: &bigEndianTimestamp) { bytes in
            buffer.append(contentsOf: bytes)
        }

        let signature = try privKey.signature(for: buffer)
        return signature
    }

    /// Completely wipes stored credentials and identity keys (re-pair flow).
    public func wipeIdentity() {
        lock.lock()
        defer { lock.unlock() }

        cachedPrivateKey = nil
        deleteFromKeychain()
        try? FileManager.default.removeItem(at: fallbackFilePath)
    }

    // MARK: - Keychain Helpers

    private func saveToKeychain(data: Data) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        SecItemAdd(query as CFDictionary, nil)
    }

    private func readFromKeychain() -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess, let data = item as? Data {
            return data
        }
        return nil
    }

    private func deleteFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount
        ]
        SecItemDelete(query as CFDictionary)
    }
}
