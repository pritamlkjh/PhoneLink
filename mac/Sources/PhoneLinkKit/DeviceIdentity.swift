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
    private let baseDirectory: URL
    private let customStorageDirectoryProvided: Bool

    private var cachedPrivateKey: Curve25519.Signing.PrivateKey?
    private let lock = NSLock()

    public init(storageDirectory: URL? = nil) {
        self.customStorageDirectoryProvided = (storageDirectory != nil)
        let baseDir = storageDirectory ?? FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first?.appendingPathComponent("com.phonelink", isDirectory: true) ?? URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("com.phonelink", isDirectory: true)
        self.baseDirectory = baseDir
        self.fallbackFilePath = baseDir.appendingPathComponent("phonelink_identity.key")
    }

    /// Retrieves existing identity private key or generates a fresh one.
    public func getOrCreatePrivateKey() -> Curve25519.Signing.PrivateKey {
        lock.lock()
        defer { lock.unlock() }

        if let cached = cachedPrivateKey {
            return cached
        }

        // 1. Try macOS Keychain first for standard host installs
        if !customStorageDirectoryProvided, let keyData = readFromKeychain() {
            if let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: keyData) {
                // Remove any stale unencrypted legacy file on disk now that Keychain holds it
                if FileManager.default.fileExists(atPath: fallbackFilePath.path) {
                    try? FileManager.default.removeItem(at: fallbackFilePath)
                }
                cachedPrivateKey = key
                return key
            }
        }

        // 2. Try isolated test / headless fallback file
        if let keyData = try? Data(contentsOf: fallbackFilePath) {
            if let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: keyData) {
                if !customStorageDirectoryProvided, saveToKeychain(data: keyData) {
                    try? FileManager.default.removeItem(at: fallbackFilePath)
                }
                cachedPrivateKey = key
                return key
            }
        }

        // 3. Generate fresh keypair; store primarily in Keychain when not isolated to a test directory
        let newKey = Curve25519.Signing.PrivateKey()
        let savedInKeychain = (!customStorageDirectoryProvided && saveToKeychain(data: newKey.rawRepresentation))
        if customStorageDirectoryProvided || !savedInKeychain {
            try? FileManager.default.createDirectory(
                at: baseDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
            if (try? newKey.rawRepresentation.write(to: fallbackFilePath, options: .atomic)) != nil {
                try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fallbackFilePath.path)
            }
        }

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

    /// Signs arbitrary bytes using the Mac device's Ed25519 identity key.
    public func sign(data: Data) throws -> Data {
        let privKey = getOrCreatePrivateKey()
        return try privKey.signature(for: data)
    }

    /// Signs an authentication challenge: (serverNonce || clientNonce || 8-byte big-endian timestamp).
    public func signChallenge(serverNonce: Data, clientNonce: Data, timestamp: Int64) throws -> Data {
        var buffer = Data()
        buffer.append(serverNonce)
        buffer.append(clientNonce)

        var bigEndianTimestamp = timestamp.bigEndian
        withUnsafeBytes(of: &bigEndianTimestamp) { bytes in
            buffer.append(contentsOf: bytes)
        }

        return try sign(data: buffer)
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

    @discardableResult
    private func saveToKeychain(data: Data) -> Bool {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]
        SecItemDelete(query as CFDictionary)
        return SecItemAdd(query as CFDictionary, nil) == errSecSuccess
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
