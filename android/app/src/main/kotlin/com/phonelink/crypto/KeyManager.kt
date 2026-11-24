package com.phonelink.crypto

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * AND-3: Android Cryptographic Key Management
 * Provides hardware-backed (where supported) signing and verification.
 */
interface KeySigner {
    val publicKeyEncoded: ByteArray
    fun sign(data: ByteArray): ByteArray
    fun verify(data: ByteArray, signature: ByteArray): Boolean
    fun isHardwareBacked(): Boolean
}

/**
 * Software EC (secp256r1) signer for JVM testing and non-Keystore environments.
 */
class SoftwareEcKeySigner(
    private val keyPair: KeyPair = generateDefaultKeyPair()
) : KeySigner {

    companion object {
        fun generateDefaultKeyPair(): KeyPair {
            val kpg = KeyPairGenerator.getInstance("EC")
            kpg.initialize(ECGenParameterSpec("secp256r1"))
            return kpg.generateKeyPair()
        }

        const val ALGORITHM = "SHA256withECDSA"
    }

    override val publicKeyEncoded: ByteArray
        get() = keyPair.public.encoded

    override fun sign(data: ByteArray): ByteArray {
        val sig = Signature.getInstance(ALGORITHM)
        sig.initSign(keyPair.private)
        sig.update(data)
        return sig.sign()
    }

    override fun verify(data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val sig = Signature.getInstance(ALGORITHM)
            sig.initVerify(keyPair.public)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }

    override fun isHardwareBacked(): Boolean = false
}

/**
 * Android Keystore implementation of KeySigner.
 * Keystore ensures the private key never leaves the secure hardware boundary.
 */
class AndroidKeyStoreSigner(
    private val keyAlias: String = DEFAULT_KEY_ALIAS
) : KeySigner {

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val DEFAULT_KEY_ALIAS = "phonelink_identity_key"
        const val ALGORITHM = "SHA256withECDSA"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    init {
        ensureKeyExists()
    }

    private fun ensureKeyExists() {
        if (!keyStore.containsAlias(keyAlias)) {
            val kpg = KeyPairGenerator.getInstance(
                "EC",
                ANDROID_KEYSTORE
            )
            // Reflection / standard spec setup so it compiles cleanly on host JVM too
            val parameterSpecClass = Class.forName("android.security.keystore.KeyGenParameterSpec\$Builder")
            val constructor = parameterSpecClass.getConstructor(String::class.java, Int::class.javaPrimitiveType)
            // PURPOSE_SIGN = 4, PURPOSE_VERIFY = 8 -> 12
            val builder = constructor.newInstance(keyAlias, 12)

            val setDigestsMethod = parameterSpecClass.getMethod("setDigests", Array<String>::class.java)
            setDigestsMethod.invoke(builder, arrayOf("SHA-256"))

            val setEcSpecMethod = parameterSpecClass.getMethod("setAlgorithmParameterSpec", java.security.spec.AlgorithmParameterSpec::class.java)
            setEcSpecMethod.invoke(builder, ECGenParameterSpec("secp256r1"))

            val buildMethod = parameterSpecClass.getMethod("build")
            val spec = buildMethod.invoke(builder) as java.security.spec.AlgorithmParameterSpec

            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
    }

    override val publicKeyEncoded: ByteArray
        get() {
            val certificate = keyStore.getCertificate(keyAlias)
                ?: throw IllegalStateException("Certificate not found for alias: $keyAlias")
            return certificate.publicKey.encoded
        }

    override fun sign(data: ByteArray): ByteArray {
        val privateKey = keyStore.getKey(keyAlias, null) as? PrivateKey
            ?: throw IllegalStateException("Private key not found for alias: $keyAlias")
        val signature = Signature.getInstance(ALGORITHM)
        signature.initSign(privateKey)
        signature.update(data)
        return signature.sign()
    }

    override fun verify(data: ByteArray, signature: ByteArray): Boolean {
        return try {
            val certificate = keyStore.getCertificate(keyAlias) ?: return false
            val sig = Signature.getInstance(ALGORITHM)
            sig.initVerify(certificate.publicKey)
            sig.update(data)
            sig.verify(signature)
        } catch (e: Exception) {
            false
        }
    }

    override fun isHardwareBacked(): Boolean {
        return try {
            val privateKey = keyStore.getKey(keyAlias, null) as? PrivateKey ?: return false
            val factoryClass = Class.forName("android.security.keystore.KeyInfo")
            val keyFactory = java.security.KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
            val getKeyInfoMethod = keyFactory.javaClass.getMethod("getKeySpec", java.security.Key::class.java, Class::class.java)
            val keyInfo = getKeyInfoMethod.invoke(keyFactory, privateKey, factoryClass)
            val isInsideSecureHardwareMethod = factoryClass.getMethod("isInsideSecureHardware")
            isInsideSecureHardwareMethod.invoke(keyInfo) as Boolean
        } catch (e: Exception) {
            false
        }
    }
}

/**
 * KeyManager orchestrates signing and verification for protocol authentication.
 */
class KeyManager(
    val signer: KeySigner
) {
    companion object {
        fun createSoftware(): KeyManager = KeyManager(SoftwareEcKeySigner())

        fun verifyExternal(publicKey: PublicKey, data: ByteArray, signature: ByteArray): Boolean {
            return try {
                val sig = Signature.getInstance("SHA256withECDSA")
                sig.initVerify(publicKey)
                sig.update(data)
                sig.verify(signature)
            } catch (e: Exception) {
                false
            }
        }
    }

    fun getPublicKeyBase64(): String {
        return Base64.getEncoder().encodeToString(signer.publicKeyEncoded)
    }

    /**
     * Signs challenge payload: (server_nonce || client_nonce || timestamp)
     */
    fun signChallenge(serverNonce: ByteArray, clientNonce: ByteArray, timestamp: Long): ByteArray {
        val buffer = java.nio.ByteBuffer.allocate(serverNonce.size + clientNonce.size + 8)
        buffer.put(serverNonce)
        buffer.put(clientNonce)
        buffer.putLong(timestamp)
        return signer.sign(buffer.array())
    }

    /**
     * Verifies signed challenge
     */
    fun verifyChallenge(serverNonce: ByteArray, clientNonce: ByteArray, timestamp: Long, signature: ByteArray): Boolean {
        val buffer = java.nio.ByteBuffer.allocate(serverNonce.size + clientNonce.size + 8)
        buffer.put(serverNonce)
        buffer.put(clientNonce)
        buffer.putLong(timestamp)
        return signer.verify(buffer.array(), signature)
    }
}
