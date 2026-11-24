package com.phonelink.storage

import android.content.Context
import android.content.SharedPreferences
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * AND-4: Android Secure Local Storage
 * Provides authenticated, encrypted storage for tokens, keys, and security preferences.
 */
class SecureStorage(
    private val preferences: SharedPreferences,
    private val encryptionKey: SecretKey = getOrCreateMasterKey(preferences)
) {
    companion object {
        private const val PREFS_FILE = "phonelink_secure_storage"
        private const val PREF_KEY_MASTER_KEY = "__secure_master_key__"
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val GCM_IV_LENGTH_BYTES = 12
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"

        const val DEFAULT_RELAY_URL = "wss://relay.phonelink.internal:8443/ws/v1/connect"

        // Storage keys
        const val KEY_SESSION_TOKEN = "session_token"
        const val KEY_PAIRED_DEVICE_ID = "paired_device_id"
        const val KEY_PAIRED_PUBLIC_KEY = "paired_public_key"
        const val KEY_RELAY_URL = "relay_url"
        const val KEY_CAMERA_ALLOWED = "camera_allowed_toggle" // Defaults to false

        private fun getOrCreateMasterKey(prefs: SharedPreferences): SecretKey {
            val encodedKey = prefs.getString(PREF_KEY_MASTER_KEY, null)
            if (encodedKey != null) {
                val raw = Base64.getDecoder().decode(encodedKey)
                return SecretKeySpec(raw, "AES")
            }
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256, SecureRandom())
            val key = kg.generateKey()
            val b64 = Base64.getEncoder().encodeToString(key.encoded)
            prefs.edit().putString(PREF_KEY_MASTER_KEY, b64).apply()
            return key
        }

        fun fromContext(context: Context): SecureStorage {
            val prefs = context.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
            return SecureStorage(prefs)
        }
    }

    private val secureRandom = SecureRandom()

    /**
     * Encrypts plaintext string using AES-256-GCM and returns Base64(IV || Ciphertext).
     */
    fun encrypt(plaintext: String): String {
        val iv = ByteArray(GCM_IV_LENGTH_BYTES)
        secureRandom.nextBytes(iv)

        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, spec)

        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val buffer = ByteBuffer.allocate(iv.size + ciphertext.size)
        buffer.put(iv)
        buffer.put(ciphertext)

        return Base64.getEncoder().encodeToString(buffer.array())
    }

    /**
     * Decrypts Base64(IV || Ciphertext) using AES-256-GCM.
     */
    fun decrypt(encodedCiphertext: String): String {
        val raw = Base64.getDecoder().decode(encodedCiphertext)
        if (raw.size < GCM_IV_LENGTH_BYTES) {
            throw IllegalArgumentException("Invalid encrypted payload size")
        }

        val buffer = ByteBuffer.wrap(raw)
        val iv = ByteArray(GCM_IV_LENGTH_BYTES)
        buffer.get(iv)

        val ciphertext = ByteArray(buffer.remaining())
        buffer.get(ciphertext)

        val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv)
        cipher.init(Cipher.DECRYPT_MODE, encryptionKey, spec)

        val plaintextBytes = cipher.doFinal(ciphertext)
        return String(plaintextBytes, Charsets.UTF_8)
    }

    fun saveString(key: String, value: String?) {
        if (value == null) {
            preferences.edit().remove(key).apply()
        } else {
            val encrypted = encrypt(value)
            preferences.edit().putString(key, encrypted).apply()
        }
    }

    fun getString(key: String, defaultValue: String? = null): String? {
        val encrypted = preferences.getString(key, null) ?: return defaultValue
        return try {
            decrypt(encrypted)
        } catch (e: Exception) {
            defaultValue
        }
    }

    fun saveSessionToken(token: String?) {
        saveString(KEY_SESSION_TOKEN, token)
    }

    fun getSessionToken(): String? {
        return getString(KEY_SESSION_TOKEN)
    }

    fun savePairedDevice(deviceId: String, publicKeyBase64: String) {
        saveString(KEY_PAIRED_DEVICE_ID, deviceId)
        saveString(KEY_PAIRED_PUBLIC_KEY, publicKeyBase64)
    }

    fun getPairedDeviceId(): String? {
        return getString(KEY_PAIRED_DEVICE_ID)
    }

    fun getPairedPublicKey(): String? {
        return getString(KEY_PAIRED_PUBLIC_KEY)
    }

    fun isPaired(): Boolean {
        return getPairedDeviceId() != null
    }

    fun clearPairing() {
        preferences.edit()
            .remove(KEY_SESSION_TOKEN)
            .remove(KEY_PAIRED_DEVICE_ID)
            .remove(KEY_PAIRED_PUBLIC_KEY)
            .apply()
    }

    fun getRelayUrl(): String {
        return getString(KEY_RELAY_URL, DEFAULT_RELAY_URL) ?: DEFAULT_RELAY_URL
    }

    fun setRelayUrl(url: String) {
        saveString(KEY_RELAY_URL, url)
    }

    /**
     * In-app Camera Authorization Gate (CAM-1 requirement).
     * Must default to FALSE.
     */
    fun isCameraAllowed(): Boolean {
        val encrypted = preferences.getString(KEY_CAMERA_ALLOWED, null) ?: return false
        return try {
            decrypt(encrypted).toBoolean()
        } catch (e: Exception) {
            false
        }
    }

    fun setCameraAllowed(allowed: Boolean) {
        saveString(KEY_CAMERA_ALLOWED, allowed.toString())
    }
}
