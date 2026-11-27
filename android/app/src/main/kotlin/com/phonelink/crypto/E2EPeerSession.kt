package com.phonelink.crypto

import org.json.JSONObject
import java.security.KeyFactory
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong
import kotlin.math.abs

/**
 * ARCH-2 / INT-1 / FILE-2 / FILE-3: Android E2E Peer Session.
 *
 * Manages authenticated ephemeral X25519 key exchange, AES-256-GCM AAD binding,
 * monotonic sequence enforcement, and application payload encryption/decryption.
 */
class E2EPeerSession(
    private val sendFunction: (ByteArray) -> Boolean,
    private val messageDispatcher: (ByteArray, (ByteArray) -> Boolean) -> ByteArray?,
    private val signer: KeySigner? = null,
    private val peerPublicKeyProvider: (() -> ByteArray?)? = null,
    private val requirePeerAuth: Boolean = false
) {
    constructor(
        sendFunction: (ByteArray) -> Boolean,
        messageDispatcher: (ByteArray) -> ByteArray?
    ) : this(
        sendFunction = sendFunction,
        messageDispatcher = { plaintext, _ -> messageDispatcher(plaintext) },
        signer = null,
        peerPublicKeyProvider = null,
        requirePeerAuth = false
    )

    companion object {
        private const val MAX_HANDSHAKE_CLOCK_SKEW_MS = 60_000L
    }

    private var sessionKeys: E2EEncryptionManager.SessionKeys? = null
    private var e2eManager: E2EEncryptionManager = E2EEncryptionManager()
    private val outgoingSeq = AtomicLong(0L)
    private var lastReceivedSeq: Long = -1L

    fun getSessionKeys(): E2EEncryptionManager.SessionKeys? = sessionKeys

    @Synchronized
    fun reset() {
        sessionKeys = null
        e2eManager = E2EEncryptionManager()
        outgoingSeq.set(0L)
        lastReceivedSeq = -1L
    }

    /**
     * Encrypts and transmits an outgoing application payload to the paired peer in strict sequence order.
     */
    @Synchronized
    fun sendApplicationMessage(payloadBytes: ByteArray): Boolean {
        val keys = sessionKeys ?: return false
        val seq = outgoingSeq.incrementAndGet()
        val aad = E2EEncryptionManager.buildPayloadAad("A2M", seq)
        val encrypted = E2EEncryptionManager.encryptAESGCM(keys.keyAndroidToMac, payloadBytes, aad)
        val respJson = JSONObject().apply {
            put("type", "E2E_PAYLOAD")
            put("seq", seq)
            put("ciphertext", Base64.getEncoder().encodeToString(encrypted))
        }
        return sendFunction(respJson.toString().toByteArray(Charsets.UTF_8))
    }

    /**
     * Handles incoming bytes from the WebSocket relay.
     * Detects authenticated E2E handshake messages or encrypted application frames.
     */
    fun handleIncomingMessage(bytes: ByteArray): Boolean {
        val text = try {
            String(bytes, Charsets.UTF_8)
        } catch (_: Exception) {
            ""
        }

        if (text.startsWith("{") && text.contains("\"type\"")) {
            val json = try {
                JSONObject(text)
            } catch (_: Exception) {
                null
            }

            if (json != null) {
                when (json.optString("type")) {
                    "E2E_INIT" -> {
                        val peerPubB64 = json.optString("ephemeral_public_key", "")
                        if (peerPubB64.isEmpty()) return false
                        val peerPubBytes = try {
                            Base64.getDecoder().decode(peerPubB64)
                        } catch (_: Exception) {
                            return false
                        }
                        val timestamp = json.optLong("timestamp", 0L)
                        val sigB64 = json.optString("signature", "")
                        return handleE2EInit(peerPubBytes, timestamp, sigB64)
                    }
                    "E2E_PAYLOAD" -> {
                        val ciphertextB64 = json.optString("ciphertext", "")
                        if (ciphertextB64.isEmpty()) return false
                        val ciphertext = try {
                            Base64.getDecoder().decode(ciphertextB64)
                        } catch (_: Exception) {
                            return false
                        }
                        val seq = if (json.has("seq")) json.optLong("seq", -1L) else -1L
                        return handleEncryptedBytes(ciphertext, seq)
                    }
                }
            }
        }

        return false
    }

    @Synchronized
    private fun handleE2EInit(peerEphemeralPubBytes: ByteArray, timestamp: Long, signatureB64: String): Boolean {
        val peerIdentityKeyBytes = peerPublicKeyProvider?.invoke()
        if (requirePeerAuth || peerIdentityKeyBytes != null) {
            if (peerIdentityKeyBytes == null || peerIdentityKeyBytes.isEmpty()) {
                return false
            }
            val nowMs = System.currentTimeMillis()
            val skewMs = if (nowMs >= timestamp) {
                nowMs.toULong() - timestamp.toULong()
            } else {
                timestamp.toULong() - nowMs.toULong()
            }
            if (timestamp <= 0L || skewMs > MAX_HANDSHAKE_CLOCK_SKEW_MS.toULong()) {
                return false
            }
            val sigBytes = try {
                Base64.getDecoder().decode(signatureB64)
            } catch (_: Exception) {
                return false
            }
            val transcript = E2EEncryptionManager.buildHandshakeTranscript(peerEphemeralPubBytes, timestamp)
            if (!verifyPeerIdentitySignature(peerIdentityKeyBytes, transcript, sigBytes)) {
                return false
            }
        }

        val peerPubKey = try {
            E2EEncryptionManager.parsePublicKey(peerEphemeralPubBytes)
        } catch (_: Exception) {
            return false
        }
        val freshManager = E2EEncryptionManager()
        val keys = try {
            freshManager.deriveSessionKeys(peerPubKey)
        } catch (_: Exception) {
            return false
        }

        val ackTimestamp = System.currentTimeMillis()
        val ownRawEph = freshManager.getRawPublicKey()
        val ackJson = try {
            JSONObject().apply {
                put("type", "E2E_ACK")
                put("ephemeral_public_key", Base64.getEncoder().encodeToString(ownRawEph))
                put("timestamp", ackTimestamp)
                if (signer != null) {
                    val transcript = E2EEncryptionManager.buildHandshakeTranscript(ownRawEph, ackTimestamp)
                    val sig = signer.sign(transcript)
                    put("signature", Base64.getEncoder().encodeToString(sig))
                }
            }
        } catch (_: Exception) {
            return false
        }

        e2eManager = freshManager
        sessionKeys = keys
        outgoingSeq.set(0L)
        lastReceivedSeq = -1L

        return sendFunction(ackJson.toString().toByteArray(Charsets.UTF_8))
    }

    private fun verifyPeerIdentitySignature(peerPubKeyBytes: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
        val rawEd = E2EEncryptionManager.extractRawEd25519PublicKey(peerPubKeyBytes)
        if (rawEd != null && signature.size == 64) {
            return Curve25519Primitives.ed25519Verify(signature, data, rawEd)
        }
        return try {
            val kf = KeyFactory.getInstance("EC")
            val ecPub = kf.generatePublic(X509EncodedKeySpec(peerPubKeyBytes))
            KeyManager.verifyExternal(ecPub, data, signature)
        } catch (_: Exception) {
            false
        }
    }

    private fun handleEncryptedBytes(ciphertext: ByteArray, seq: Long): Boolean {
        val keys = synchronized(this) { sessionKeys } ?: return false

        val aad: ByteArray? = synchronized(this) {
            if (seq >= 0L) {
                if (seq <= lastReceivedSeq) {
                    return false
                }
                E2EEncryptionManager.buildPayloadAad("M2A", seq)
            } else {
                if (requirePeerAuth) {
                    return false
                }
                null
            }
        }

        val plaintext = try {
            E2EEncryptionManager.decryptAESGCM(keys.keyMacToAndroid, ciphertext, aad)
        } catch (_: Exception) {
            return false
        }

        if (seq >= 0L) {
            synchronized(this) {
                if (seq <= lastReceivedSeq) {
                    return false
                }
                lastReceivedSeq = seq
            }
        }

        val sendAppMsg: (ByteArray) -> Boolean = { payload ->
            sendApplicationMessage(payload)
        }

        val responseBytes = messageDispatcher(plaintext, sendAppMsg) ?: return true
        sendApplicationMessage(responseBytes)
        return true
    }
}
