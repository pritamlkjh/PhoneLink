package com.phonelink.security

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.util.UUID

class ReplayProtectionFilterTest {

    private var simulatedTime: Long = 100_000_000L
    private lateinit var filter: ReplayProtectionFilter

    @Before
    fun setUp() {
        simulatedTime = 100_000_000L
        filter = ReplayProtectionFilter(
            maxClockSkewMs = 60_000L, // 60s
            maxCacheSize = 100,
            timeProvider = { simulatedTime }
        )
    }

    private fun createMessage(msgId: String = UUID.randomUUID().toString(), ts: Long = simulatedTime): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", 1)
            put("message_id", msgId)
            put("timestamp", ts)
            put("device_ping_req", JSONObject().apply {
                put("request_id", "req-1")
            })
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    @Test
    fun testValidFreshMessageAccepted() {
        val msg = createMessage("msg-1", simulatedTime)
        val result = filter.validateMessage(msg)
        assertTrue(result is ReplayProtectionFilter.ValidationResult.Valid)
        assertEquals(1L, filter.getTotalValidated())
        assertEquals(0L, filter.getTotalReplayed())
    }

    @Test
    fun testReplayedDuplicateMessageIdRejected() {
        val msg = createMessage("msg-duplicate", simulatedTime)

        // First message is valid
        val firstResult = filter.validateMessage(msg)
        assertTrue(firstResult is ReplayProtectionFilter.ValidationResult.Valid)

        // Advance clock slightly (10 seconds)
        simulatedTime += 10_000L

        // Replaying same message_id must be rejected
        val secondResult = filter.validateMessage(msg)
        assertTrue(secondResult is ReplayProtectionFilter.ValidationResult.Rejected)
        val rejected = secondResult as ReplayProtectionFilter.ValidationResult.Rejected
        assertEquals(ReplayProtectionFilter.STATUS_REPLAY_DETECTED, rejected.status)
        assertEquals(1L, filter.getTotalReplayed())
    }

    @Test
    fun testExpiredOldTimestampRejected() {
        // Message timestamp 70 seconds in past (> 60s max skew)
        val oldTimestamp = simulatedTime - 70_000L
        val msg = createMessage("msg-old", oldTimestamp)

        val result = filter.validateMessage(msg)
        assertTrue(result is ReplayProtectionFilter.ValidationResult.Rejected)
        val rejected = result as ReplayProtectionFilter.ValidationResult.Rejected
        assertEquals(ReplayProtectionFilter.STATUS_MESSAGE_EXPIRED, rejected.status)
        assertEquals(1L, filter.getTotalExpired())
    }

    @Test
    fun testFutureTimestampExceedingSkewRejected() {
        // Message timestamp 70 seconds in future
        val futureTimestamp = simulatedTime + 70_000L
        val msg = createMessage("msg-future", futureTimestamp)

        val result = filter.validateMessage(msg)
        assertTrue(result is ReplayProtectionFilter.ValidationResult.Rejected)
        val rejected = result as ReplayProtectionFilter.ValidationResult.Rejected
        assertEquals(ReplayProtectionFilter.STATUS_MESSAGE_EXPIRED, rejected.status)
        assertEquals(1L, filter.getTotalExpired())
    }

    @Test
    fun testMalformedMissingAttributesHandledSafely() {
        // 1. Missing message_id
        val noId = JSONObject().apply {
            put("timestamp", simulatedTime)
        }.toString().toByteArray(Charsets.UTF_8)
        val resNoId = filter.validateMessage(noId)
        assertTrue(resNoId is ReplayProtectionFilter.ValidationResult.Rejected)
        assertEquals(ReplayProtectionFilter.STATUS_MALFORMED_MESSAGE, (resNoId as ReplayProtectionFilter.ValidationResult.Rejected).status)

        // 2. Missing timestamp
        val noTs = JSONObject().apply {
            put("message_id", "some-id")
        }.toString().toByteArray(Charsets.UTF_8)
        val resNoTs = filter.validateMessage(noTs)
        assertTrue(resNoTs is ReplayProtectionFilter.ValidationResult.Rejected)
        assertEquals(ReplayProtectionFilter.STATUS_MALFORMED_MESSAGE, (resNoTs as ReplayProtectionFilter.ValidationResult.Rejected).status)

        // 3. Random non-JSON binary garbage
        val garbage = byteArrayOf(0x00, 0x1F, 0x7E, 0xFF.toByte(), 0x88.toByte())
        val resGarbage = filter.validateMessage(garbage)
        assertTrue(resGarbage is ReplayProtectionFilter.ValidationResult.Rejected)
        assertEquals(ReplayProtectionFilter.STATUS_MALFORMED_MESSAGE, (resGarbage as ReplayProtectionFilter.ValidationResult.Rejected).status)
    }

    @Test
    fun testBuildErrorResponseFormat() {
        val errBytes = filter.buildErrorResponse(
            ReplayProtectionFilter.STATUS_REPLAY_DETECTED,
            "Replay detected for test"
        )
        assertNotNull(errBytes)
        val json = JSONObject(String(errBytes, Charsets.UTF_8))
        assertEquals(1, json.getInt("schema_version"))
        assertTrue(json.has("message_id"))
        assertEquals(simulatedTime, json.getLong("timestamp"))
        assertTrue(json.has("error"))
        val errObj = json.getJSONObject("error")
        assertEquals(ReplayProtectionFilter.STATUS_REPLAY_DETECTED, errObj.getString("code"))
        assertEquals("Replay detected for test", errObj.getString("message"))
    }
}
