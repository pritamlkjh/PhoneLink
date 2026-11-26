package com.phonelink.identity

import android.content.Context
import android.content.SharedPreferences
import com.phonelink.crypto.KeyManager
import com.phonelink.crypto.KeySigner
import com.phonelink.crypto.SoftwareEcKeySigner
import com.phonelink.storage.SecureStorage
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * AND-2: Android Device Identity Provisioning
 * Manages the stable, cryptographically-derived device identity.
 */
class DeviceIdentityManager(
    private val preferences: SharedPreferences,
    private val signer: KeySigner? = null
) {
    companion object {
        private const val PREF_KEY_PUBLIC_KEY = "device_identity_public_key"
        private const val PREF_KEY_PRIVATE_KEY = "device_identity_private_key"
        private const val PREF_KEY_DEVICE_ID = "device_identity_device_id"

        fun fromContext(
            context: Context,
            keyManager: KeyManager = KeyManager.fromContext(context, SecureStorage.fromContext(context))
        ): DeviceIdentityManager {
            val prefs = context.getSharedPreferences("phonelink_identity", Context.MODE_PRIVATE)
            return DeviceIdentityManager(prefs, keyManager.signer)
        }

        fun bytesToHex(bytes: ByteArray): String {
            return bytes.joinToString("") { "%02x".format(it) }
        }

        fun hexToBytes(hex: String): ByteArray {
            check(hex.length % 2 == 0) { "Must have an even length" }
            return hex.chunked(2)
                .map { it.toInt(16).toByte() }
                .toByteArray()
        }
    }

    data class Identity(
        val deviceId: String,
        val publicKeyEncoded: ByteArray,
        val privateKeyEncoded: ByteArray
    )

    private var cachedIdentity: Identity? = null

    /**
     * Retrieves the existing identity or generates a new one on first launch.
     */
    @Synchronized
    fun getOrCreateIdentity(): Identity {
        if (signer != null) {
            val pubKeyBytes = signer.publicKeyEncoded
            val expectedDeviceId = bytesToHex(MessageDigest.getInstance("SHA-256").digest(pubKeyBytes))
            val existingCached = cachedIdentity
            if (existingCached != null &&
                existingCached.deviceId == expectedDeviceId &&
                existingCached.publicKeyEncoded.contentEquals(pubKeyBytes)
            ) {
                return existingCached
            }

            val pubBase64 = Base64.getEncoder().encodeToString(pubKeyBytes)
            if (preferences.getString(PREF_KEY_DEVICE_ID, null) != expectedDeviceId ||
                preferences.getString(PREF_KEY_PUBLIC_KEY, null) != pubBase64 ||
                preferences.contains(PREF_KEY_PRIVATE_KEY)
            ) {
                preferences.edit()
                    .putString(PREF_KEY_DEVICE_ID, expectedDeviceId)
                    .putString(PREF_KEY_PUBLIC_KEY, pubBase64)
                    .remove(PREF_KEY_PRIVATE_KEY)
                    .apply()
            }

            val boundIdentity = Identity(
                deviceId = expectedDeviceId,
                publicKeyEncoded = pubKeyBytes,
                privateKeyEncoded = ByteArray(0)
            )
            cachedIdentity = boundIdentity
            return boundIdentity
        }

        cachedIdentity?.let { return it }

        val storedDeviceId = preferences.getString(PREF_KEY_DEVICE_ID, null)
        val storedPubKey = preferences.getString(PREF_KEY_PUBLIC_KEY, null)
        val storedPrivKey = preferences.getString(PREF_KEY_PRIVATE_KEY, null)

        if (storedDeviceId != null && storedPubKey != null && storedPrivKey != null) {
            val identity = Identity(
                deviceId = storedDeviceId,
                publicKeyEncoded = Base64.getDecoder().decode(storedPubKey),
                privateKeyEncoded = Base64.getDecoder().decode(storedPrivKey)
            )
            cachedIdentity = identity
            return identity
        }

        // Generate fresh keypair
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair: KeyPair = kpg.generateKeyPair()

        val pubKeyBytes = keyPair.public.encoded
        val privKeyBytes = keyPair.private.encoded

        // Derive device_id = HEX(SHA-256(publicKey))
        val sha256 = MessageDigest.getInstance("SHA-256")
        val digest = sha256.digest(pubKeyBytes)
        val deviceId = bytesToHex(digest)

        // Persist to private preferences
        val pubBase64 = Base64.getEncoder().encodeToString(pubKeyBytes)
        val privBase64 = Base64.getEncoder().encodeToString(privKeyBytes)

        preferences.edit()
            .putString(PREF_KEY_DEVICE_ID, deviceId)
            .putString(PREF_KEY_PUBLIC_KEY, pubBase64)
            .putString(PREF_KEY_PRIVATE_KEY, privBase64)
            .apply()

        val newIdentity = Identity(
            deviceId = deviceId,
            publicKeyEncoded = pubKeyBytes,
            privateKeyEncoded = privKeyBytes
        )
        cachedIdentity = newIdentity
        return newIdentity
    }

    fun toKeyManager(): KeyManager {
        if (signer != null) return KeyManager(signer)
        val id = getOrCreateIdentity()
        return KeyManager(SoftwareEcKeySigner.fromEncoded(id.publicKeyEncoded, id.privateKeyEncoded))
    }

    /**
     * Returns the 64-character hex device ID.
     */
    fun getDeviceId(): String {
        return getOrCreateIdentity().deviceId
    }

    /**
     * Simulates a reinstall by clearing stored identity.
     */
    fun clearIdentity() {
        cachedIdentity = null
        preferences.edit().clear().apply()
    }
}
