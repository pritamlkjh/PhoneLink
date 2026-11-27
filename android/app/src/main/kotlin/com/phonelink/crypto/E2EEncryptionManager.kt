package com.phonelink.crypto

import java.nio.ByteBuffer
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ARCH-2 / INT-1: End-to-End Encryption Manager.
 *
 * Implements:
 * 1. Ephemeral Diffie-Hellman Key Exchange (portable RFC 7748 X25519 across API 26+)
 * 2. HKDF-SHA256 key derivation (producing directional keys K_M2A and K_A2M)
 * 3. Authenticated Symmetric Encryption (AES-256-GCM with 96-bit random IV and AAD binding)
 * 4. Identity verification helpers for authenticated E2E handshakes (Ed25519 / ECDSA P-256)
 */
class E2EEncryptionManager(
    val ephemeralKeyPair: KeyPair = generateEphemeralKeyPair()
) {
    class X25519PublicKey(val rawBytes: ByteArray) : PublicKey {
        init {
            require(rawBytes.size == KEY_SIZE_BYTES) { "X25519 public key must be 32 bytes" }
        }
        override fun getAlgorithm(): String = "X25519"
        override fun getFormat(): String = "X.509"
        override fun getEncoded(): ByteArray = X25519_X509_HEADER + rawBytes
    }

    class X25519PrivateKey(val rawBytes: ByteArray) : PrivateKey {
        init {
            require(rawBytes.size == KEY_SIZE_BYTES) { "X25519 private key must be 32 bytes" }
        }
        override fun getAlgorithm(): String = "X25519"
        override fun getFormat(): String = "PKCS#8"
        override fun getEncoded(): ByteArray = X25519_PKCS8_HEADER + rawBytes
    }

    companion object {
        const val KEY_SIZE_BYTES = 32
        const val GCM_IV_BYTES = 12
        const val GCM_TAG_BITS = 128
        const val INFO_M2A = "PhoneLink-M2A-v1"
        const val INFO_A2M = "PhoneLink-A2M-v1"

        private val X25519_X509_HEADER = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00
        )
        private val ED25519_X509_HEADER = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
        )
        private val X25519_PKCS8_HEADER = byteArrayOf(
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20
        )

        fun generateEphemeralKeyPair(): KeyPair {
            val priv = Curve25519Primitives.x25519GeneratePrivateKey()
            val pub = Curve25519Primitives.x25519PublicFromPrivate(priv)
            return KeyPair(X25519PublicKey(pub), X25519PrivateKey(priv))
        }

        fun buildHandshakeTranscript(ephemeralPublicKey: ByteArray, timestampMs: Long): ByteArray {
            val buf = ByteBuffer.allocate(ephemeralPublicKey.size + 8)
            buf.put(ephemeralPublicKey)
            buf.putLong(timestampMs)
            return buf.array()
        }

        fun buildPayloadAad(direction: String, seq: Long): ByteArray {
            return "PhoneLink-E2E-v1|$direction|$seq".toByteArray(Charsets.UTF_8)
        }

        fun extractRawEd25519PublicKey(rawOrDer: ByteArray): ByteArray? {
            return when {
                rawOrDer.size == KEY_SIZE_BYTES -> rawOrDer
                rawOrDer.size == ED25519_X509_HEADER.size + KEY_SIZE_BYTES &&
                    rawOrDer.copyOfRange(0, ED25519_X509_HEADER.size).contentEquals(ED25519_X509_HEADER) ->
                    rawOrDer.copyOfRange(ED25519_X509_HEADER.size, rawOrDer.size)
                else -> null
            }
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

        fun parsePublicKey(rawOrDer: ByteArray): PublicKey {
            val raw = when {
                rawOrDer.size == KEY_SIZE_BYTES -> rawOrDer.copyOf()
                rawOrDer.size == X25519_X509_HEADER.size + KEY_SIZE_BYTES &&
                    rawOrDer.copyOfRange(0, X25519_X509_HEADER.size).contentEquals(X25519_X509_HEADER) ->
                    rawOrDer.copyOfRange(X25519_X509_HEADER.size, rawOrDer.size)
                else -> throw IllegalArgumentException("Unsupported X25519 public key length (${rawOrDer.size} bytes)")
            }
            return X25519PublicKey(raw)
        }
    }

    data class SessionKeys(
        val keyMacToAndroid: ByteArray,
        val keyAndroidToMac: ByteArray
    )

    fun getPublicKeyEncoded(): ByteArray = ephemeralKeyPair.public.encoded

    fun getRawPublicKey(): ByteArray {
        val pub = ephemeralKeyPair.public
        if (pub is X25519PublicKey) return pub.rawBytes.copyOf()
        val encoded = pub.encoded
        return if (encoded.size == 44 && encoded[0] == 0x30.toByte()) {
            encoded.copyOfRange(12, 44)
        } else {
            encoded
        }
    }

    /**
     * Completes X25519 ECDH with peer's ephemeral public key and derives directional keys.
     */
    fun deriveSessionKeys(peerPublicKey: PublicKey, salt: ByteArray = ByteArray(32)): SessionKeys {
        val privRaw = when (val priv = ephemeralKeyPair.private) {
            is X25519PrivateKey -> priv.rawBytes
            else -> {
                val enc = priv.encoded
                if (enc.size >= KEY_SIZE_BYTES) enc.copyOfRange(enc.size - KEY_SIZE_BYTES, enc.size)
                else throw IllegalStateException("Unsupported private key encoding")
            }
        }
        val peerRaw = when (peerPublicKey) {
            is X25519PublicKey -> peerPublicKey.rawBytes
            else -> parsePublicKey(peerPublicKey.encoded).let { (it as X25519PublicKey).rawBytes }
        }
        val sharedSecret = Curve25519Primitives.x25519ComputeSharedSecret(privRaw, peerRaw)

        val prk = hkdfExtract(salt, sharedSecret)
        val kM2A = hkdfExpand(prk, INFO_M2A.toByteArray(Charsets.UTF_8), KEY_SIZE_BYTES)
        val kA2M = hkdfExpand(prk, INFO_A2M.toByteArray(Charsets.UTF_8), KEY_SIZE_BYTES)

        return SessionKeys(
            keyMacToAndroid = kM2A,
            keyAndroidToMac = kA2M
        )
    }
}
