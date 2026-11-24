package com.phonelink.transport

import android.content.SharedPreferences
import com.phonelink.auth.AuthClient
import com.phonelink.crypto.KeyManager
import com.phonelink.identity.DeviceIdentityManager
import com.phonelink.storage.SecureStorage
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.security.KeyPairGenerator
import java.util.Base64
import java.util.Random
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ReconnectionManagerTest {

    private class MockSharedPreferences : SharedPreferences {
        private val data = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = data
        override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = null
        override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun edit(): SharedPreferences.Editor = MockEditor(data)
        override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

        private class MockEditor(private val data: MutableMap<String, Any?>) : SharedPreferences.Editor {
            private val temp = mutableMapOf<String, Any?>()
            private val removes = mutableSetOf<String>()
            private var clear = false

            override fun putString(key: String?, value: String?): SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun remove(key: String?): SharedPreferences.Editor {
                if (key != null) removes.add(key)
                return this
            }
            override fun clear(): SharedPreferences.Editor {
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

    private class MockNetworkStateProvider(var isAvailable: Boolean = true) :
        ReconnectionManager.NetworkStateProvider {
        var onAvailableCallback: (() -> Unit)? = null
        var onLostCallback: (() -> Unit)? = null
        var isRegistered = false

        override fun isNetworkAvailable(): Boolean = isAvailable

        override fun registerCallback(onAvailable: () -> Unit, onLost: () -> Unit) {
            this.onAvailableCallback = onAvailable
            this.onLostCallback = onLost
            this.isRegistered = true
        }

        override fun unregisterCallback() {
            this.onAvailableCallback = null
            this.onLostCallback = null
            this.isRegistered = false
        }

        fun triggerNetworkAvailable() {
            isAvailable = true
            onAvailableCallback?.invoke()
        }

        fun triggerNetworkLost() {
            isAvailable = false
            onLostCallback?.invoke()
        }
    }

    private lateinit var mockWebServer: MockWebServer
    private lateinit var secureStorage: SecureStorage
    private lateinit var identityManager: DeviceIdentityManager
    private lateinit var keyManager: KeyManager
    private lateinit var authClient: AuthClient
    private lateinit var networkProvider: MockNetworkStateProvider
    private lateinit var reconnectionManager: ReconnectionManager

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()

        val mockPrefs = MockSharedPreferences()
        secureStorage = SecureStorage(mockPrefs)
        identityManager = DeviceIdentityManager(mockPrefs)
        keyManager = KeyManager.createSoftware()
        authClient = AuthClient(secureStorage = secureStorage)
        networkProvider = MockNetworkStateProvider(isAvailable = true)

        reconnectionManager = ReconnectionManager(
            authClient = authClient,
            secureStorage = secureStorage,
            identityManager = identityManager,
            keyManager = keyManager,
            networkStateProvider = networkProvider,
            config = ReconnectionManager.ReconnectConfig(
                baseDelayMillis = 1000L,
                maxDelayMillis = 30000L,
                backoffFactor = 2.0
            ),
            random = Random(12345),
            scheduler = Executors.newSingleThreadScheduledExecutor()
        )
    }

    @After
    fun tearDown() {
        reconnectionManager.stop()
        mockWebServer.shutdown()
    }

    @Test
    fun testJitteredExponentialBackoffCalculations() {
        // Attempt 0 -> 0ms
        assertEquals(0L, reconnectionManager.calculateBackoffDelay(0))

        // Attempt 1: base = 1000ms -> min = 500ms, max = 1000ms
        val delay1 = reconnectionManager.calculateBackoffDelay(1)
        assertTrue(delay1 in 500L..1000L, "delay1 out of bounds: $delay1")

        // Attempt 2: base = 2000ms -> min = 1000ms, max = 2000ms
        val delay2 = reconnectionManager.calculateBackoffDelay(2)
        assertTrue(delay2 in 1000L..2000L, "delay2 out of bounds: $delay2")

        // Attempt 3: base = 4000ms -> min = 2000ms, max = 4000ms
        val delay3 = reconnectionManager.calculateBackoffDelay(3)
        assertTrue(delay3 in 2000L..4000L, "delay3 out of bounds: $delay3")

        // Attempt 10: max capped at 30000ms -> min = 15000ms, max = 30000ms
        val delay10 = reconnectionManager.calculateBackoffDelay(10)
        assertTrue(delay10 in 15000L..30000L, "delay10 out of bounds: $delay10")
    }

    @Test
    fun testNetworkLossTransitionsToWaitingForNetwork() {
        val baseUrl = mockWebServer.url("").toString().removeSuffix("/")

        // Mock initial challenge + verify responses for start()
        val serverNonce = ByteArray(32).also { Random().nextBytes(it) }
        val ts = System.currentTimeMillis()
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                JSONObject().put("status", "OK")
                    .put("server_nonce", Base64.getEncoder().encodeToString(serverNonce))
                    .put("timestamp", ts).toString()
            )
        )
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                JSONObject().put("status", "OK")
                    .put("session_token", "test-session-token-1")
                    .put("resumption_token", "test-resume-token-1")
                    .put("resumption_ttl_seconds", 300).toString()
            )
        )

        reconnectionManager.start(baseUrl)
        Thread.sleep(100) // Allow async worker to complete

        assertTrue(reconnectionManager.getState() is ReconnectionManager.State.Connected)

        // Trigger network lost (e.g. airplane mode enabled)
        networkProvider.triggerNetworkLost()

        assertEquals(ReconnectionManager.State.WaitingForNetwork, reconnectionManager.getState())

        // Trigger network restored (e.g. Wi-Fi connected) -> should immediately reconnect
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                JSONObject().put("status", "OK")
                    .put("session_token", "test-session-token-resumed")
                    .put("resumption_token", "test-resume-token-2")
                    .put("resumption_ttl_seconds", 300).toString()
            )
        )

        networkProvider.triggerNetworkAvailable()
        Thread.sleep(100)

        assertTrue(reconnectionManager.getState() is ReconnectionManager.State.Connected)
    }

    @Test
    fun testFastSessionResumptionWhenTokenValid() {
        val baseUrl = mockWebServer.url("").toString().removeSuffix("/")

        // Pre-populate secureStorage with a valid resumption token
        secureStorage.saveResumptionToken("valid-resumption-token-abc", System.currentTimeMillis() + 60000)

        // Enqueue successful resume response
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                JSONObject().put("status", "OK")
                    .put("session_token", "new-resumed-session-token")
                    .put("resumption_token", "rotated-resumption-token-xyz")
                    .put("resumption_ttl_seconds", 300).toString()
            )
        )

        var wasResumedObserved: Boolean? = null
        var sessionTokenObserved: String? = null

        reconnectionManager.addListener(object : ReconnectionManager.Listener {
            override fun onReconnectionSucceeded(sessionToken: String, wasResumed: Boolean) {
                sessionTokenObserved = sessionToken
                wasResumedObserved = wasResumed
            }
        })

        reconnectionManager.start(baseUrl)
        Thread.sleep(100)

        val recordedReq = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertNotNull(recordedReq)
        assertEquals("/api/v1/auth/resume", recordedReq.path)

        val reqJson = JSONObject(recordedReq.body.readUtf8())
        assertEquals("valid-resumption-token-abc", reqJson.getString("resumption_token"))

        assertTrue(wasResumedObserved == true, "Expected wasResumed=true")
        assertEquals("new-resumed-session-token", sessionTokenObserved)
        assertEquals("new-resumed-session-token", secureStorage.getSessionToken())
        assertEquals("rotated-resumption-token-xyz", secureStorage.getResumptionToken())
    }

    @Test
    fun testFallbackToFullAuthWhenResumptionRejected() {
        val baseUrl = mockWebServer.url("").toString().removeSuffix("/")

        // Pre-populate with an expired/rejected resumption token
        secureStorage.saveResumptionToken("stale-resumption-token", System.currentTimeMillis() + 60000)

        // 1. Resume fails with 401 Unauthorized
        mockWebServer.enqueue(
            MockResponse().setResponseCode(401).setBody(
                JSONObject().put("error", "resumption token not found or expired").toString()
            )
        )

        // 2. Fallback to Challenge
        val serverNonce = ByteArray(32).also { Random().nextBytes(it) }
        val ts = System.currentTimeMillis()
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                JSONObject().put("status", "OK")
                    .put("server_nonce", Base64.getEncoder().encodeToString(serverNonce))
                    .put("timestamp", ts).toString()
            )
        )

        // 3. Fallback to Verify
        mockWebServer.enqueue(
            MockResponse().setResponseCode(200).setBody(
                JSONObject().put("status", "OK")
                    .put("session_token", "fresh-full-auth-token")
                    .put("resumption_token", "fresh-resumption-token")
                    .put("resumption_ttl_seconds", 300).toString()
            )
        )

        var wasResumedObserved: Boolean? = null
        var sessionTokenObserved: String? = null

        reconnectionManager.addListener(object : ReconnectionManager.Listener {
            override fun onReconnectionSucceeded(sessionToken: String, wasResumed: Boolean) {
                sessionTokenObserved = sessionToken
                wasResumedObserved = wasResumed
            }
        })

        reconnectionManager.start(baseUrl)
        Thread.sleep(150)

        // Request 1: /api/v1/auth/resume (failed)
        val req1 = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("/api/v1/auth/resume", req1?.path)

        // Request 2: /api/v1/auth/challenge (fallback)
        val req2 = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("/api/v1/auth/challenge", req2?.path)

        // Request 3: /api/v1/auth/verify (fallback)
        val req3 = mockWebServer.takeRequest(1, TimeUnit.SECONDS)
        assertEquals("/api/v1/auth/verify", req3?.path)

        assertTrue(wasResumedObserved == false, "Expected wasResumed=false for fallback full auth")
        assertEquals("fresh-full-auth-token", sessionTokenObserved)
        assertEquals("fresh-full-auth-token", secureStorage.getSessionToken())
        assertEquals("fresh-resumption-token", secureStorage.getResumptionToken())
    }
}
