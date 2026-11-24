package com.phonelink.security

import org.json.JSONObject
import java.util.LinkedHashMap
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

/**
 * SEC-1: Cross-Component Replay Protection Filter.
 *
 * Enforces replay protection and clock-skew bounds across all incoming ApplicationMessages:
 * 1. Clock-Skew / Freshness Check:
 *    Rejects messages whose timestamp deviates from current time by more than maxClockSkewMs.
 * 2. Message Nonce / ID Deduplication:
 *    Tracks recently seen message_ids in a synchronized bounded LRU cache to detect
 *    and reject replayed messages with STATUS_REPLAY_DETECTED.
 * 3. Message Format Validation:
 *    Ensures message_id and timestamp are valid before passing to subsystems.
 */
class ReplayProtectionFilter(
    private val maxClockSkewMs: Long = DEFAULT_MAX_CLOCK_SKEW_MS,
    private val maxCacheSize: Int = DEFAULT_MAX_CACHE_SIZE,
    private val timeProvider: () -> Long = { System.currentTimeMillis() }
) {
    companion object {
        const val DEFAULT_MAX_CLOCK_SKEW_MS = 60_000L // 60 seconds allowable skew
        const val DEFAULT_MAX_CACHE_SIZE = 5_000

        const val STATUS_OK = "STATUS_OK"
        const val STATUS_MESSAGE_EXPIRED = "STATUS_MESSAGE_EXPIRED"
        const val STATUS_REPLAY_DETECTED = "STATUS_REPLAY_DETECTED"
        const val STATUS_MALFORMED_MESSAGE = "STATUS_MALFORMED_MESSAGE"
    }

    sealed class ValidationResult {
        object Valid : ValidationResult()
        data class Rejected(val status: String, val message: String) : ValidationResult()
    }

    // Thread-safe bounded LRU cache for message_ids
    private val seenMessageIds = object : LinkedHashMap<String, Long>(maxCacheSize, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean {
            return size > maxCacheSize
        }
    }

    private val totalValidated = AtomicLong(0)
    private val totalReplayed = AtomicLong(0)
    private val totalExpired = AtomicLong(0)
    private val totalMalformed = AtomicLong(0)

    fun getTotalValidated(): Long = totalValidated.get()
    fun getTotalReplayed(): Long = totalReplayed.get()
    fun getTotalExpired(): Long = totalExpired.get()
    fun getTotalMalformed(): Long = totalMalformed.get()

    @Synchronized
    fun validateMessage(plaintext: ByteArray): ValidationResult {
        val text = try {
            String(plaintext, Charsets.UTF_8)
        } catch (_: Exception) {
            totalMalformed.incrementAndGet()
            return ValidationResult.Rejected(STATUS_MALFORMED_MESSAGE, "Payload contains invalid UTF-8 data")
        }

        val json = try {
            JSONObject(text)
        } catch (_: Exception) {
            totalMalformed.incrementAndGet()
            return ValidationResult.Rejected(STATUS_MALFORMED_MESSAGE, "Payload is not valid JSON")
        }

        val messageId = json.optString("message_id", "")
        if (messageId.isEmpty()) {
            totalMalformed.incrementAndGet()
            return ValidationResult.Rejected(STATUS_MALFORMED_MESSAGE, "Missing required 'message_id' attribute")
        }

        val timestamp = json.optLong("timestamp", 0L)
        if (timestamp <= 0L) {
            totalMalformed.incrementAndGet()
            return ValidationResult.Rejected(STATUS_MALFORMED_MESSAGE, "Missing or non-positive 'timestamp' attribute")
        }

        val now = timeProvider()
        val skew = Math.abs(now - timestamp)

        // 1. Clock skew freshness verification
        if (skew > maxClockSkewMs) {
            totalExpired.incrementAndGet()
            return ValidationResult.Rejected(
                STATUS_MESSAGE_EXPIRED,
                "Message timestamp ($timestamp) exceeds max allowable clock skew (${skew}ms > ${maxClockSkewMs}ms)"
            )
        }

        // 2. Replay detection check
        if (seenMessageIds.containsKey(messageId)) {
            totalReplayed.incrementAndGet()
            return ValidationResult.Rejected(
                STATUS_REPLAY_DETECTED,
                "Duplicate message_id '$messageId' rejected by replay protection filter"
            )
        }

        // Periodically purge records older than 2x clock skew
        val purgeThreshold = now - (maxClockSkewMs * 2)
        val iterator = seenMessageIds.entries.iterator()
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value < purgeThreshold) {
                iterator.remove()
            } else {
                break
            }
        }

        seenMessageIds[messageId] = timestamp
        totalValidated.incrementAndGet()
        return ValidationResult.Valid
    }

    /**
     * Builds a compliant ApplicationMessage error response for rejected messages.
     */
    fun buildErrorResponse(status: String, message: String): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", 1)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", timeProvider())
            put("error", JSONObject().apply {
                put("code", status)
                put("message", message)
            })
        }
        return root.toString().toByteArray(Charsets.UTF_8)
    }

    @Synchronized
    fun reset() {
        seenMessageIds.clear()
        totalValidated.set(0)
        totalReplayed.set(0)
        totalExpired.set(0)
        totalMalformed.set(0)
    }
}
