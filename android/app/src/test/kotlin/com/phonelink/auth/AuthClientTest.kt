package com.phonelink.auth

import com.phonelink.crypto.KeyManager
import com.phonelink.identity.DeviceIdentityManager
import com.phonelink.storage.SecureStorage
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class AuthClientTest {

    private class MockSharedPreferences : android.content.SharedPreferences {
        private val data = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = data
        override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = null
        override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun edit(): android.content.SharedPreferences.Editor = MockEditor(data)
        override fun registerOnSharedPreferenceChangeListener(listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}

        private class MockEditor(private val data: MutableMap<String, Any?>) : android.content.SharedPreferences.Editor {
            private val temp = mutableMapOf<String, Any?>()
            private val removes = mutableSetOf<String>()
            private var clear = false

            override fun putString(key: String?, value: String?): android.content.SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun putStringSet(key: String?, values: MutableSet<String>?): android.content.SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): android.content.SharedPreferences.Editor = this
            override fun putLong(key: String?, value: Long): android.content.SharedPreferences.Editor = this
            override fun putFloat(key: String?, value: Float): android.content.SharedPreferences.Editor = this
            override fun putBoolean(key: String?, value: Boolean): android.content.SharedPreferences.Editor = this
            override fun remove(key: String?): android.content.SharedPreferences.Editor {
                if (key != null) removes.add(key)
                return this
            }
            override fun clear(): android.content.SharedPreferences.Editor {
                clear = true
                return this
            }
            override fun commit(): Boolean {
                apply()
                return true
            }
            override fun apply() {
                if (clear) data.clear()
                removes.forEach { data.remove(it) }
                data.putAll(temp)
            }
        }
    }

    private lateinit var mockWebServer: MockWebServer
    private lateinit var secureStorage: SecureStorage
    private lateinit var identityManager: DeviceIdentityManager
    private lateinit var keyManager: KeyManager
    private lateinit var authClient: AuthClient

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        val mockPrefs = MockSharedPreferences()
        secureStorage = SecureStorage(mockPrefs)
        identityManager = DeviceIdentityManager(mockPrefs)
        keyManager = KeyManager.createSoftware()
        authClient = AuthClient(secureStorage = secureStorage)
    }

    @After
    fun tearDown() {
        mockWebServer.shutdown()
    }

    @Test
    fun testRegisterDeviceSuccess() {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(201)
                .setBody(JSONObject(mapOf("status" to "OK", "device_id" to identityManager.getDeviceId())).toString())
        )

        val vpsUrl = mockWebServer.url("").toString().removeSuffix("/")
        val result = authClient.registerDevice(vpsUrl, identityManager)

        assertTrue(result.isSuccess, "Device registration should succeed: ${result.exceptionOrNull()}")
        val recordedReq = mockWebServer.takeRequest()
        assertEquals("/api/v1/devices/register", recordedReq.path)
        assertTrue(recordedReq.body.readUtf8().contains("ECDSA_P256"))
    }

    @Test
    fun testHandshakeSuccessAndTokenSavedInSecureStorage() {
        val serverNonce = ByteArray(32) { (it + 1).toByte() }
        val serverNonceB64 = Base64.getEncoder().encodeToString(serverNonce)
        val timestamp = System.currentTimeMillis()

        // Challenge response
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(JSONObject(mapOf("status" to "OK", "server_nonce" to serverNonceB64, "timestamp" to timestamp)).toString())
        )

        // Verify response
        val expectedSessionToken = "sess_android_verified_token_12345"
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(JSONObject(mapOf("status" to "OK", "session_token" to expectedSessionToken, "peer_online" to false)).toString())
        )

        val vpsUrl = mockWebServer.url("").toString().removeSuffix("/")
        val result = authClient.authenticate(vpsUrl, identityManager, keyManager)

        assertTrue(result.isSuccess, "Auth handshake should succeed: ${result.exceptionOrNull()}")
        val sessionToken = result.getOrThrow()
        assertEquals(expectedSessionToken, sessionToken)

        // Verify token saved to SecureStorage (AND-4)
        val savedToken = secureStorage.getSessionToken()
        assertEquals(expectedSessionToken, savedToken, "Session token must be persisted in SecureStorage")
    }

    @Test
    fun testHandshakeRejectedOnUnauthorizedDevice() {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody(JSONObject(mapOf("error" to "unregistered or revoked device")).toString())
        )

        val vpsUrl = mockWebServer.url("").toString().removeSuffix("/")
        val result = authClient.authenticate(vpsUrl, identityManager, keyManager)

        assertTrue(result.isFailure, "Handshake must fail on 401 Unauthorized")
        val ex = result.exceptionOrNull()
        assertNotNull(ex)
        assertTrue(ex.message!!.contains("401"))
    }

    @Test
    fun testPairingClaimSuccess() {
        val pairedMacId = "mac_device_paired_peer_6789"
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(JSONObject(mapOf("status" to "OK", "paired_peer_id" to pairedMacId)).toString())
        )

        val vpsUrl = mockWebServer.url("").toString().removeSuffix("/")
        val result = authClient.claimPairing(vpsUrl, "pair_token_abc123", identityManager)

        assertTrue(result.isSuccess)
        assertEquals(pairedMacId, result.getOrThrow())
        assertEquals(pairedMacId, secureStorage.getPairedDeviceId())
    }

    @Test
    fun testGetDeviceStatusSuccess() {
        val pairedMacId = "mac_device_paired_peer_6789"
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(200)
                .setBody(
                    JSONObject().apply {
                        put("device_id", identityManager.getDeviceId())
                        put("is_online", true)
                        put("is_paired", true)
                        put("peer_device_id", pairedMacId)
                        put("peer_online", true)
                        put("timestamp", 1234567890L)
                    }.toString()
                )
        )

        val vpsUrl = mockWebServer.url("").toString().removeSuffix("/")
        val result = authClient.getDeviceStatus(vpsUrl, "valid_session_token")

        assertTrue(result.isSuccess)
        val status = result.getOrThrow()
        assertEquals(identityManager.getDeviceId(), status.deviceId)
        assertTrue(status.isOnline)
        assertTrue(status.isPaired)
        assertEquals(pairedMacId, status.peerDeviceId)
        assertTrue(status.peerOnline)
        assertEquals(1234567890L, status.timestamp)
    }

    @Test
    fun testGetDeviceStatusUnauthorized() {
        mockWebServer.enqueue(
            MockResponse()
                .setResponseCode(401)
                .setBody("{\"error\":\"unauthorized: invalid session token\"}")
        )

        val vpsUrl = mockWebServer.url("").toString().removeSuffix("/")
        val result = authClient.getDeviceStatus(vpsUrl, "invalid_session_token")

        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.contains("401"))
    }
}
