import Foundation
import CryptoKit

/// ARCH-2 / INT-1: Swift End-to-End Encryption Manager
/// Implements X25519 key exchange, HKDF key derivation, and AES-256-GCM / ChaChaPoly AEAD encryption.
public final class E2EEncryptionManager: @unchecked Sendable {
    public static let infoM2A = Data("PhoneLink-M2A-v1".utf8)
    public static let infoA2M = Data("PhoneLink-A2M-v1".utf8)
    private static let ed25519X509Prefix = Data([0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00])

    public static func buildHandshakeTranscript(ephemeralPublicKey: Data, timestampMs: Int64) -> Data {
        var data = Data(ephemeralPublicKey)
        var be = timestampMs.bigEndian
        withUnsafeBytes(of: &be) { bytes in
            data.append(contentsOf: bytes)
        }
        return data
    }

    public static func buildPayloadAad(direction: String, seq: Int64) -> Data {
        return Data("PhoneLink-E2E-v1|\(direction)|\(seq)".utf8)
    }

    public static func verifyPeerSignature(publicKeyBytes: Data, algorithm: String?, message: Data, signature: Data) -> Bool {
        let alg = (algorithm ?? "").uppercased()
        if alg.contains("ED25519") || (publicKeyBytes.count == 32 && signature.count == 64 && alg.isEmpty) {
            let rawKey: Data
            if publicKeyBytes.count == 32 {
                rawKey = publicKeyBytes
            } else if publicKeyBytes.count == 44 && publicKeyBytes.prefix(12) == ed25519X509Prefix {
                rawKey = publicKeyBytes.subdata(in: 12..<44)
            } else {
                return false
            }
            guard let edPub = try? Curve25519.Signing.PublicKey(rawRepresentation: rawKey) else {
                return false
            }
            return edPub.isValidSignature(signature, for: message)
        }

        if let p256Pub = try? P256.Signing.PublicKey(derRepresentation: publicKeyBytes),
           let ecdsaSig = try? P256.Signing.ECDSASignature(derRepresentation: signature) {
            return p256Pub.isValidSignature(ecdsaSig, for: message)
        }
        if let p256Raw = try? P256.Signing.PublicKey(x963Representation: publicKeyBytes),
           let ecdsaSig = try? P256.Signing.ECDSASignature(derRepresentation: signature) {
            return p256Raw.isValidSignature(ecdsaSig, for: message)
        }
        return false
    }

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
