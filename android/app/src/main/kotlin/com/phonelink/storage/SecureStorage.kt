package com.phonelink.storage

import android.content.Context
import android.content.SharedPreferences
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Security
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
        private const val PREF_KEY_WRAPPED_MASTER_KEY = "__secure_master_key_wrapped__"
        private const val KEYSTORE_WRAP_ALIAS = "phonelink_storage_master_wrap"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val GCM_TAG_LENGTH_BITS = 128
        private const val GCM_IV_LENGTH_BYTES = 12
        private const val CIPHER_TRANSFORMATION = "AES/GCM/NoPadding"

        const val DEFAULT_RELAY_URL = ""

        // Storage keys
        const val KEY_SESSION_TOKEN = "session_token"
        const val KEY_PAIRED_DEVICE_ID = "paired_device_id"
        const val KEY_PAIRED_PUBLIC_KEY = "paired_public_key"
        const val KEY_RELAY_URL = "relay_url"
        const val KEY_CAMERA_ALLOWED = "camera_allowed_toggle" // Defaults to false
        const val KEY_REMOTE_PING_ALLOWED = "remote_ping_allowed_toggle" // Defaults to true
        const val KEY_REMOTE_INFO_ALLOWED = "remote_info_allowed_toggle" // Defaults to true
        const val KEY_RESUMPTION_TOKEN = "resumption_token"
        const val KEY_RESUMPTION_EXPIRES_AT = "resumption_expires_at"
        const val KEY_AUTO_START_ON_BOOT = "auto_start_on_boot"
        const val KEY_SOFTWARE_IDENTITY_PUB = "software_identity_pub_key"
        const val KEY_SOFTWARE_IDENTITY_PRIV = "software_identity_priv_key"
        const val KEY_SCOPED_TREE_URI = "scoped_tree_uri"

        private fun hasAndroidKeyStore(): Boolean {
            return try {
                Security.getProvider(ANDROID_KEYSTORE) != null
            } catch (_: Throwable) {
                false
            }
        }

        private fun getOrCreateKeyStoreWrapKey(): SecretKey {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val existing = ks.getKey(KEYSTORE_WRAP_ALIAS, null) as? SecretKey
            if (existing != null) return existing

            val kg = KeyGenerator.getInstance("AES", ANDROID_KEYSTORE)
            val builderClass = Class.forName("android.security.keystore.KeyGenParameterSpec\$Builder")
            // PURPOSE_ENCRYPT = 1, PURPOSE_DECRYPT = 2 -> 3
            val ctor = builderClass.getConstructor(String::class.java, Int::class.javaPrimitiveType)
            val builder = ctor.newInstance(KEYSTORE_WRAP_ALIAS, 3)

            builderClass.getMethod("setBlockModes", Array<String>::class.java)
                .invoke(builder, arrayOf("GCM"))
            builderClass.getMethod("setEncryptionPaddings", Array<String>::class.java)
                .invoke(builder, arrayOf("NoPadding"))
            builderClass.getMethod("setKeySize", Int::class.javaPrimitiveType)
                .invoke(builder, 256)

            val spec = builderClass.getMethod("build").invoke(builder) as java.security.spec.AlgorithmParameterSpec
            kg.init(spec)
            return kg.generateKey()
        }

        private fun wrapMasterKeyWithKeystore(rawKey: ByteArray): String {
            val wrapKey = getOrCreateKeyStoreWrapKey()
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, wrapKey)
            val iv = cipher.iv
            val wrapped = cipher.doFinal(rawKey)
            val buf = ByteBuffer.allocate(iv.size + wrapped.size)
            buf.put(iv)
            buf.put(wrapped)
            return Base64.getEncoder().encodeToString(buf.array())
        }

        private fun unwrapMasterKeyWithKeystore(wrappedB64: String): SecretKey {
            val wrapKey = getOrCreateKeyStoreWrapKey()
            val raw = Base64.getDecoder().decode(wrappedB64)
            require(raw.size > GCM_IV_LENGTH_BYTES) { "Invalid wrapped key" }
            val iv = raw.copyOfRange(0, GCM_IV_LENGTH_BYTES)
            val ciphertext = raw.copyOfRange(GCM_IV_LENGTH_BYTES, raw.size)
            val cipher = Cipher.getInstance(CIPHER_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, wrapKey, GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv))
            val unwrapped = cipher.doFinal(ciphertext)
            return SecretKeySpec(unwrapped, "AES")
        }

        private fun getOrCreateMasterKey(prefs: SharedPreferences): SecretKey {
            if (hasAndroidKeyStore()) {
                val wrapped = prefs.getString(PREF_KEY_WRAPPED_MASTER_KEY, null)
                if (wrapped != null) {
                    try {
                        return unwrapMasterKeyWithKeystore(wrapped)
                    } catch (_: Throwable) {
                        // Vendor Keystore corruption/invalidation (e.g., OEM OTA or lock-screen reset):
                        // scrub unreadable wrapped blob rather than crash-looping on startup.
                        prefs.edit().remove(PREF_KEY_WRAPPED_MASTER_KEY).apply()
                    }
                }

                // Reuse any existing app-private software fallback key, or generate a new 256-bit key
                val legacyEncoded = prefs.getString(PREF_KEY_MASTER_KEY, null)
                val rawKey = if (legacyEncoded != null) {
                    try {
                        Base64.getDecoder().decode(legacyEncoded)
                    } catch (_: Throwable) {
                        generateRawAes256Key()
                    }
                } else {
                    generateRawAes256Key()
                }

                try {
                    val newWrapped = wrapMasterKeyWithKeystore(rawKey)
                    prefs.edit()
                        .putString(PREF_KEY_WRAPPED_MASTER_KEY, newWrapped)
                        .remove(PREF_KEY_MASTER_KEY)
                        .apply()
                    return SecretKeySpec(rawKey, "AES")
                } catch (_: Throwable) {
                    // Vendor Keystore unavailable/broken for AES/GCM wrapping: fall through to app-private fallback
                    val b64 = Base64.getEncoder().encodeToString(rawKey)
                    prefs.edit().putString(PREF_KEY_MASTER_KEY, b64).apply()
                    return SecretKeySpec(rawKey, "AES")
                }
            }

            // Host JVM / software fallback when AndroidKeyStore provider is unavailable
            val encodedKey = prefs.getString(PREF_KEY_MASTER_KEY, null)
            if (encodedKey != null) {
                try {
                    val raw = Base64.getDecoder().decode(encodedKey)
                    return SecretKeySpec(raw, "AES")
                } catch (_: Throwable) {}
            }
            val rawKey = generateRawAes256Key()
            val b64 = Base64.getEncoder().encodeToString(rawKey)
            prefs.edit().putString(PREF_KEY_MASTER_KEY, b64).apply()
            return SecretKeySpec(rawKey, "AES")
        }

        private fun generateRawAes256Key(): ByteArray {
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256, SecureRandom())
            return kg.generateKey().encoded
        }

        internal fun hasWrappedKey(prefs: SharedPreferences): Boolean =
            prefs.contains(PREF_KEY_WRAPPED_MASTER_KEY)

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

    /**
     * In-app Remote Ping Authorization Gate (FILE-5 requirement).
     * Defaults to TRUE.
     */
    fun isRemotePingAllowed(): Boolean {
        val encrypted = preferences.getString(KEY_REMOTE_PING_ALLOWED, null) ?: return true
        return try {
            decrypt(encrypted).toBoolean()
        } catch (_: Exception) {
            true
        }
    }

    fun setRemotePingAllowed(allowed: Boolean) {
        saveString(KEY_REMOTE_PING_ALLOWED, allowed.toString())
    }

    /**
     * In-app Remote Info Authorization Gate (FILE-5 requirement).
     * Defaults to TRUE.
     */
    fun isRemoteInfoAllowed(): Boolean {
        val encrypted = preferences.getString(KEY_REMOTE_INFO_ALLOWED, null) ?: return true
        return try {
            decrypt(encrypted).toBoolean()
        } catch (_: Exception) {
            true
        }
    }

    fun setRemoteInfoAllowed(allowed: Boolean) {
        saveString(KEY_REMOTE_INFO_ALLOWED, allowed.toString())
    }

    /**
     * Session Resumption Token Storage (AND-8 / VPS-6).
     * Bounded validity window.
     */
    fun saveResumptionToken(token: String?, expiresAtMillis: Long) {
        if (token == null) {
            preferences.edit()
                .remove(KEY_RESUMPTION_TOKEN)
                .remove(KEY_RESUMPTION_EXPIRES_AT)
                .apply()
        } else {
            saveString(KEY_RESUMPTION_TOKEN, token)
            preferences.edit().putLong(KEY_RESUMPTION_EXPIRES_AT, expiresAtMillis).apply()
        }
    }

    fun getResumptionToken(): String? {
        val token = getString(KEY_RESUMPTION_TOKEN) ?: return null
        val expiresAt = preferences.getLong(KEY_RESUMPTION_EXPIRES_AT, 0L)
        if (System.currentTimeMillis() >= expiresAt) {
            clearResumptionToken()
            return null
        }
        return token
    }

    fun clearResumptionToken() {
        saveResumptionToken(null, 0L)
    }

    /**
     * Boot Auto-Start Setting (AND-9).
     * Defaults to true.
     */
    fun isAutoStartOnBoot(): Boolean {
        return preferences.getBoolean(KEY_AUTO_START_ON_BOOT, true)
    }

    fun setAutoStartOnBoot(enabled: Boolean) {
        preferences.edit().putBoolean(KEY_AUTO_START_ON_BOOT, enabled).apply()
    }

    fun getScopedTreeUri(): String? {
        return getString(KEY_SCOPED_TREE_URI)
    }

    fun setScopedTreeUri(uriString: String?) {
        saveString(KEY_SCOPED_TREE_URI, uriString)
    }
}
