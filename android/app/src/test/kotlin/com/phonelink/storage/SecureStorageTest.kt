package com.phonelink.storage

import com.phonelink.identity.InMemorySharedPreferences
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class SecureStorageTest {

    private lateinit var mockPrefs: InMemorySharedPreferences
    private lateinit var storage: SecureStorage

    @Before
    fun setUp() {
        mockPrefs = InMemorySharedPreferences()
        storage = SecureStorage(mockPrefs)
    }

    @Test
    fun testSessionTokenEncryption() {
        val plainToken = "jwt_session_secret_token_abc_123"
        storage.saveSessionToken(plainToken)

        // Verify stored value in raw preferences is encrypted and NOT plaintext
        val rawStoredValue = mockPrefs.getString(SecureStorage.KEY_SESSION_TOKEN, null)
        assertNotNull(rawStoredValue)
        assertFalse(rawStoredValue.contains(plainToken), "Raw preferences must NEVER store plaintext tokens")

        // Decrypt via SecureStorage
        val retrieved = storage.getSessionToken()
        assertEquals(plainToken, retrieved, "Decrypted token must match original plaintext")
    }

    @Test
    fun testPairingStorageAndClear() {
        assertFalse(storage.isPaired())
        assertNull(storage.getPairedDeviceId())

        val macDeviceId = "mac_device_id_9876543210"
        val macPubKeyB64 = "MCowBQYDK2VwAyEA94/XbO"
        storage.savePairedDevice(macDeviceId, macPubKeyB64)

        assertTrue(storage.isPaired())
        assertEquals(macDeviceId, storage.getPairedDeviceId())
        assertEquals(macPubKeyB64, storage.getPairedPublicKey())

        storage.clearPairing()
        assertFalse(storage.isPaired())
        assertNull(storage.getPairedDeviceId())
        assertNull(storage.getPairedPublicKey())
    }

    @Test
    fun testCameraAllowedDefaultsToFalse() {
        // Crucial security requirement from REQ-1 and CAM-1: Camera must be OFF by default!
        assertFalse(storage.isCameraAllowed(), "Camera toggle MUST default to false on fresh install")

        storage.setCameraAllowed(true)
        assertTrue(storage.isCameraAllowed(), "Camera toggle should be true after explicit enablement")

        storage.setCameraAllowed(false)
        assertFalse(storage.isCameraAllowed(), "Camera toggle should be false after explicit disablement")
    }

    @Test
    fun testRelayUrlDefaultAndCustom() {
        assertEquals(SecureStorage.DEFAULT_RELAY_URL, storage.getRelayUrl())

        val customUrl = "wss://vps.myownrelay.net:8443/ws/v1/connect"
        storage.setRelayUrl(customUrl)
        assertEquals(customUrl, storage.getRelayUrl())
    }

    @Test
    fun testTamperedCiphertextFailsGracefully() {
        storage.saveString("test_key", "secret_value")

        // Tamper with the raw ciphertext
        mockPrefs.edit().putString("test_key", "tampered_non_base64_or_invalid_tag").apply()

        val result = storage.getString("test_key", "fallback_default")
        assertEquals("fallback_default", result, "Tampered ciphertext must fail authentication and return fallback")
    }
}
