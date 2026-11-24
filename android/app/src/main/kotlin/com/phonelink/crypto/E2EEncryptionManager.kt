package com.phonelink.crypto

import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ARCH-2 / INT-1: End-to-End Encryption Manager.
 *
 * Implements:
 * 1. Ephemeral Diffie-Hellman Key Exchange (X25519 / XDH)
 * 2. HKDF-SHA256 key derivation (producing directional keys K_M2A and K_A2M)
 * 3. Authenticated Symmetric Encryption (AES-256-GCM with 96-bit random IV)
 *
 * Security Invariant:
 * The VPS relay never possesses or derives these keys, and can never decrypt payloads.
 */
class E2EEncryptionManager(
    val ephemeralKeyPair: KeyPair = generateEphemeralKeyPair()
) {
    companion object {
        const val KEY_SIZE_BYTES = 32
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val INFO_M2A = "PhoneLink-M2A-v1"
        const val INFO_A2M = "PhoneLink-A2M-v1"

        fun generateEphemeralKeyPair(): KeyPair {
            val kpg = try {
                KeyPairGenerator.getInstance("X25519")
            } catch (e: Exception) {
                try {
                    KeyPairGenerator.getInstance("XDH")
                } catch (e2: Exception) {
                    // Fallback for older JVMs to standard EC
                    val k = KeyPairGenerator.getInstance("EC")
                    k.initialize(256)
                    k
                }
            }
            return kpg.generateKeyPair()
        }

        fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray {
            val actualSalt = if (salt.isEmpty()) ByteArray(32) else salt
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(actualSalt, "HmacSHA256"))
            return mac.doFinal(ikm)
        }

        fun hkdfExpand(prk: ByteArray, info: ByteArray, length: Int): ByteArray {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(SecretKeySpec(prk, "HmacSHA256"))
            val result = ByteArray(length)
            var t = ByteArray(0)
            var offset = 0
            var i: Byte = 1

            while (offset < length) {
                mac.reset()
                mac.update(t)
                mac.update(info)
                mac.update(i)
                t = mac.doFinal()
                val bytesToCopy = minOf(t.size, length - offset)
                System.arraycopy(t, 0, result, offset, bytesToCopy)
                offset += bytesToCopy
                i++
            }
            return result
        }

        fun encryptAESGCM(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray {
            val iv = ByteArray(GCM_IV_BYTES)
            SecureRandom().nextBytes(iv)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, iv)
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec)

            if (aad != null && aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }

            val ciphertext = cipher.doFinal(plaintext)
            val output = ByteBuffer.allocate(iv.size + ciphertext.size)
            output.put(iv)
            output.put(ciphertext)
            return output.array()
        }

        fun decryptAESGCM(key: ByteArray, payload: ByteArray, aad: ByteArray? = null): ByteArray {
            if (payload.size < GCM_IV_BYTES) {
                throw IllegalArgumentException("Payload too short for GCM IV")
            }

            val buffer = ByteBuffer.wrap(payload)
            val iv = ByteArray(GCM_IV_BYTES)
            buffer.get(iv)

            val ciphertext = ByteArray(buffer.remaining())
            buffer.get(ciphertext)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val keySpec = SecretKeySpec(key, "AES")
            val gcmSpec = GCMParameterSpec(GCM_TAG_BITS, iv)
            cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec)

            if (aad != null && aad.isNotEmpty()) {
                cipher.updateAAD(aad)
            }

            return cipher.doFinal(ciphertext)
        }
    }

    data class SessionKeys(
        val keyMacToAndroid: ByteArray,
        val keyAndroidToMac: ByteArray
    )

    fun getPublicKeyEncoded(): ByteArray = ephemeralKeyPair.public.encoded

    /**
     * Completes ECDH with peer's ephemeral public key and derives directional keys.
     */
    fun deriveSessionKeys(peerPublicKey: PublicKey, salt: ByteArray = ByteArray(32)): SessionKeys {
        val ka = try {
            KeyAgreement.getInstance("X25519")
        } catch (e: Exception) {
            try {
                KeyAgreement.getInstance("XDH")
            } catch (e2: Exception) {
                KeyAgreement.getInstance("ECDH")
            }
        }
        ka.init(ephemeralKeyPair.private)
        ka.doPhase(peerPublicKey, true)
        val sharedSecret = ka.generateSecret()

        val prk = hkdfExtract(salt, sharedSecret)
        val kM2A = hkdfExpand(prk, INFO_M2A.toByteArray(Charsets.UTF_8), KEY_SIZE_BYTES)
        val kA2M = hkdfExpand(prk, INFO_A2M.toByteArray(Charsets.UTF_8), KEY_SIZE_BYTES)

        return SessionKeys(
            keyMacToAndroid = kM2A,
            keyAndroidToMac = kA2M
        )
    }
}
