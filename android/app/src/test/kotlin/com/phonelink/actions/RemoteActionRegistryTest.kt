package com.phonelink.actions

import com.phonelink.identity.InMemorySharedPreferences
import com.phonelink.storage.SecureStorage
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

class RemoteActionRegistryTest {

    private lateinit var mockPrefs: InMemorySharedPreferences
    private lateinit var storage: SecureStorage
    private lateinit var testTelemetry: TestTelemetryProvider
    private lateinit var testFeedback: TestFeedbackController
    private lateinit var registry: RemoteActionRegistry

    class TestTelemetryProvider : RemoteActionRegistry.TelemetryProvider {
        var testModel = "Google Pixel 8 Pro"
        var testOsVersion = "Android 14 (API 34)"
        var testBatteryPercent = 92
        var testIsCharging = true
        var testTotalStorageBytes = 256_000_000_000L
        var testAvailableStorageBytes = 180_000_000_000L
        var testAppVersion = "1.0.0-test"

        override fun getModel(): String = testModel
        override fun getOsVersion(): String = testOsVersion
        override fun getBatteryPercent(): Int = testBatteryPercent
        override fun isCharging(): Boolean = testIsCharging
        override fun getTotalStorageBytes(): Long = testTotalStorageBytes
        override fun getAvailableStorageBytes(): Long = testAvailableStorageBytes
        override fun getAppVersion(): String = testAppVersion
    }

    class TestFeedbackController : RemoteActionRegistry.ActionFeedbackController {
        var pingDuration: Int? = null
        val executedActions = mutableListOf<String>()

        override fun triggerPing(durationSeconds: Int) {
            pingDuration = durationSeconds
        }

        override fun notifyActionExecuted(actionName: String) {
            executedActions.add(actionName)
        }
    }

    @Before
    fun setUp() {
        mockPrefs = InMemorySharedPreferences()
        storage = SecureStorage(mockPrefs)
        storage.setRemotePingAllowed(true)
        storage.setRemoteInfoAllowed(true)

        testTelemetry = TestTelemetryProvider()
        testFeedback = TestFeedbackController()

        registry = RemoteActionRegistry(
            secureStorage = storage,
            telemetryProvider = testTelemetry,
            feedbackController = testFeedback
        )
    }

    @Test
    fun testBuildTimeAllowlistStrictness() {
        assertTrue(registry.isActionAllowlisted("device.ping"))
        assertTrue(registry.isActionAllowlisted("device.info"))

        // Security check: Verify no arbitrary command actions are ever allowlisted
        assertFalse(registry.isActionAllowlisted("shell.exec"))
        assertFalse(registry.isActionAllowlisted("system.reboot"))
        assertFalse(registry.isActionAllowlisted("rm -rf"))
        assertFalse(registry.isActionAllowlisted("eval"))
        assertFalse(registry.isActionAllowlisted("device.locate_gps"))
        assertEquals(2, RemoteActionRegistry.ALLOWED_ACTIONS.size)
    }

    @Test
    fun testPingExecutionWithValidDuration() {
        val resp = registry.executePing(durationSeconds = 12, requestId = "req-123")
        assertEquals("req-123", resp.requestId)
        assertEquals(RemoteActionRegistry.STATUS_OK, resp.status)
        assertEquals(12, testFeedback.pingDuration)
        assertTrue(testFeedback.executedActions.contains("device.ping"))
    }

    @Test
    fun testPingDurationClampingAndBounds() {
        // Duration 0 -> default 5 seconds
        val respDefault = registry.executePing(durationSeconds = 0)
        assertEquals(RemoteActionRegistry.STATUS_OK, respDefault.status)
        assertEquals(RemoteActionRegistry.DEFAULT_PING_DURATION_SECONDS, testFeedback.pingDuration)

        // Duration 60 -> capped to MAX 30 seconds
        val respCapped = registry.executePing(durationSeconds = 60)
        assertEquals(RemoteActionRegistry.STATUS_OK, respCapped.status)
        assertEquals(RemoteActionRegistry.MAX_PING_DURATION_SECONDS, testFeedback.pingDuration)

        // Negative duration -> rejected as invalid argument
        testFeedback.pingDuration = null
        val respNegative = registry.executePing(durationSeconds = -5)
        assertEquals(RemoteActionRegistry.STATUS_INVALID_ARGUMENT, respNegative.status)
        assertNull(testFeedback.pingDuration)
    }

    @Test
    fun testPingGatedWhenPermissionDisabled() {
        storage.setRemotePingAllowed(false)

        val resp = registry.executePing(durationSeconds = 10, requestId = "req-denied")
        assertEquals("req-denied", resp.requestId)
        assertEquals(RemoteActionRegistry.STATUS_ACTION_NOT_PERMITTED, resp.status)
        assertNull(testFeedback.pingDuration)
    }

    @Test
    fun testDeviceInfoRetrieval() {
        val resp = registry.executeInfo(requestId = "info-999")
        assertEquals("info-999", resp.requestId)
        assertEquals(RemoteActionRegistry.STATUS_OK, resp.status)
        assertEquals("Google Pixel 8 Pro", resp.model)
        assertEquals("Android 14 (API 34)", resp.osVersion)
        assertEquals(92, resp.batteryPercent)
        assertTrue(resp.isCharging)
        assertEquals(256_000_000_000L, resp.totalStorageBytes)
        assertEquals(180_000_000_000L, resp.availableStorageBytes)
        assertEquals("1.0.0-test", resp.appVersion)
        assertTrue(testFeedback.executedActions.contains("device.info"))
    }

    @Test
    fun testDeviceInfoGatedWhenPermissionDisabled() {
        storage.setRemoteInfoAllowed(false)

        val resp = registry.executeInfo(requestId = "info-blocked")
        assertEquals("info-blocked", resp.requestId)
        assertEquals(RemoteActionRegistry.STATUS_ACTION_NOT_PERMITTED, resp.status)
        assertEquals("", resp.model)
    }

    @Test
    fun testArbitraryCommandInjectionRejection() {
        // Attempting to send shell command injection in payload
        val attackJson = JSONObject().apply {
            put("shell_cmd", "cat /etc/passwd")
            put("request_id", "attack-1")
        }
        val attackBytes = attackJson.toString().toByteArray(Charsets.UTF_8)
        val respBytes = registry.processApplicationMessage(attackBytes)

        assertNotNull(respBytes)
        val respJson = JSONObject(String(respBytes!!, Charsets.UTF_8))
        assertTrue(respJson.has("error"))
        val err = respJson.getJSONObject("error")
        assertEquals("attack-1", err.getString("request_id"))
        assertEquals(RemoteActionRegistry.STATUS_ACTION_NOT_PERMITTED, err.getString("code"))

        // Attempting to invoke unknown action
        val unknownActionJson = JSONObject().apply {
            val req = JSONObject().apply {
                put("action", "remote_reboot")
                put("request_id", "attack-2")
            }
            put("action_request", req)
        }
        val unknownRespBytes = registry.processApplicationMessage(unknownActionJson.toString().toByteArray(Charsets.UTF_8))
        assertNotNull(unknownRespBytes)
        val unknownRespJson = JSONObject(String(unknownRespBytes!!, Charsets.UTF_8))
        assertTrue(unknownRespJson.has("error"))
        assertEquals(RemoteActionRegistry.STATUS_ACTION_NOT_PERMITTED, unknownRespJson.getJSONObject("error").getString("code"))
    }

    @Test
    fun testApplicationMessageSerializationAndDispatch() {
        // Test Ping request dispatch
        val pingReqJson = JSONObject().apply {
            put("schema_version", 1)
            val req = JSONObject().apply {
                put("request_id", "req-ping-42")
                put("duration_seconds", 15)
            }
            put("device_ping_req", req)
        }
        val pingRespBytes = registry.processApplicationMessage(pingReqJson.toString().toByteArray(Charsets.UTF_8))
        assertNotNull(pingRespBytes)
        val pingRespJson = JSONObject(String(pingRespBytes!!, Charsets.UTF_8))
        assertTrue(pingRespJson.has("device_ping_resp"))
        val pingResp = pingRespJson.getJSONObject("device_ping_resp")
        assertEquals("req-ping-42", pingResp.getString("request_id"))
        assertEquals(RemoteActionRegistry.STATUS_OK, pingResp.getString("status"))
        assertEquals(15, testFeedback.pingDuration)

        // Test Info request dispatch
        val infoReqJson = JSONObject().apply {
            put("schema_version", 1)
            val req = JSONObject().apply {
                put("request_id", "req-info-77")
            }
            put("device_info_req", req)
        }
        val infoRespBytes = registry.processApplicationMessage(infoReqJson.toString().toByteArray(Charsets.UTF_8))
        assertNotNull(infoRespBytes)
        val infoRespJson = JSONObject(String(infoRespBytes!!, Charsets.UTF_8))
        assertTrue(infoRespJson.has("device_info_resp"))
        val infoResp = infoRespJson.getJSONObject("device_info_resp")
        assertEquals("req-info-77", infoResp.getString("request_id"))
        assertEquals(RemoteActionRegistry.STATUS_OK, infoResp.getString("status"))
        assertEquals("Google Pixel 8 Pro", infoResp.getString("model"))
    }
}
