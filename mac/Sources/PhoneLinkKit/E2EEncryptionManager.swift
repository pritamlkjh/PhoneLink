import Foundation
import CryptoKit

/// ARCH-2 / INT-1: Swift End-to-End Encryption Manager
/// Implements X25519 key exchange, HKDF key derivation, and AES-256-GCM / ChaChaPoly AEAD encryption.
public final class E2EEncryptionManager: @unchecked Sendable {
    public static let infoM2A = "PhoneLink-M2A-v1".data(using: .utf8)!
    public static let infoA2M = "PhoneLink-A2M-v1".data(using: .utf8)!

    public struct SessionKeys: Sendable {
        public let keyMacToAndroid: SymmetricKey
        public let keyAndroidToMac: SymmetricKey

        public init(keyMacToAndroid: SymmetricKey, keyAndroidToMac: SymmetricKey) {
            self.keyMacToAndroid = keyMacToAndroid
            self.keyAndroidToMac = keyAndroidToMac
        }
    }

    public let privateKey: Curve25519.KeyAgreement.PrivateKey
    public var publicKey: Curve25519.KeyAgreement.PublicKey { privateKey.publicKey }
    public var publicKeyRaw: Data { privateKey.publicKey.rawRepresentation }

    public init(privateKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
    }

    /// Derives directional session keys K_M2A and K_A2M from peer's X25519 public key.
    public func deriveSessionKeys(peerPublicKeyData: Data, salt: Data = Data(count: 32)) throws -> SessionKeys {
        let peerKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKeyData)
        let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: peerKey)

        let kM2A = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Self.infoM2A,
            outputByteCount: 32
        )

        let kA2M = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: Self.infoA2M,
            outputByteCount: 32
        )

        return SessionKeys(keyMacToAndroid: kM2A, keyAndroidToMac: kA2M)
    }

    /// Encrypts plaintext data with AES-256-GCM: format is (12-byte IV || ciphertext || 16-byte tag).
    public static func encryptAESGCM(key: SymmetricKey, plaintext: Data, aad: Data? = nil) throws -> Data {
        let sealedBox = try AES.GCM.seal(plaintext, using: key, authenticating: aad ?? Data())
        guard let combined = sealedBox.combined else {
            throw CryptoKitError.underlyingCoreCryptoError(error: 1)
        }
        return combined
    }

    /// Decrypts AES-256-GCM payload: format is (12-byte IV || ciphertext || 16-byte tag).
    public static func decryptAESGCM(key: SymmetricKey, payload: Data, aad: Data? = nil) throws -> Data {
        let sealedBox = try AES.GCM.SealedBox(combined: payload)
        return try AES.GCM.open(sealedBox, using: key, authenticating: aad ?? Data())
    }
}
