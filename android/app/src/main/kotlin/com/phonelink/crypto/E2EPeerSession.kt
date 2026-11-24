package com.phonelink.crypto

import org.json.JSONObject
import java.util.Base64

/**
 * ARCH-2 / INT-1 / FILE-2: Android E2E Peer Session.
 *
 * Manages the ephemeral key exchange and transparent encryption/decryption of
 * application layer messages with the paired Mac client.
 */
class E2EPeerSession(
    private val sendFunction: (ByteArray) -> Boolean,
    private val messageDispatcher: (ByteArray) -> ByteArray?
) {
    private var sessionKeys: E2EEncryptionManager.SessionKeys? = null
    private var e2eManager: E2EEncryptionManager = E2EEncryptionManager()

    fun getSessionKeys(): E2EEncryptionManager.SessionKeys? = sessionKeys

    fun reset() {
        sessionKeys = null
        e2eManager = E2EEncryptionManager()
    }

    /**
     * Handles incoming bytes from the WebSocket relay.
     * Detects E2E handshake messages or encrypted application frames.
     */
    fun handleIncomingMessage(bytes: ByteArray): Boolean {
        // 1. Check for JSON control frames (E2E_INIT, E2E_ACK, E2E_PAYLOAD)
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
                        val peerPubB64 = json.optString("ephemeral_public_key")
                        val peerPubBytes = Base64.getDecoder().decode(peerPubB64)
                        handleE2EInit(peerPubBytes)
                        return true
                    }
                    "E2E_PAYLOAD" -> {
                        val ciphertextB64 = json.optString("ciphertext")
                        val ciphertext = Base64.getDecoder().decode(ciphertextB64)
                        handleEncryptedBytes(ciphertext)
                        return true
                    }
                }
            }
        }

        // 2. Handle raw binary AES-GCM ciphertext frame directly (minimum IV + Tag = 28 bytes)
        val keys = sessionKeys
        if (keys != null && bytes.size >= E2EEncryptionManager.GCM_IV_BYTES + 16) {
            val processed = handleEncryptedBytes(bytes)
            if (processed) return true
        }

        return false
    }

    private fun handleE2EInit(peerEphemeralPubBytes: ByteArray) {
        val peerPubKey = E2EEncryptionManager.parsePublicKey(peerEphemeralPubBytes)
        val keys = e2eManager.deriveSessionKeys(peerPubKey)
        sessionKeys = keys

        val ackJson = JSONObject().apply {
            put("type", "E2E_ACK")
            put("ephemeral_public_key", Base64.getEncoder().encodeToString(e2eManager.getRawPublicKey()))
            put("timestamp", System.currentTimeMillis())
        }
        sendFunction(ackJson.toString().toByteArray(Charsets.UTF_8))
    }

    private fun handleEncryptedBytes(ciphertext: ByteArray): Boolean {
        val keys = sessionKeys ?: return false

        val plaintext = try {
            E2EEncryptionManager.decryptAESGCM(keys.keyMacToAndroid, ciphertext)
        } catch (_: Exception) {
            return false
        }

        val responseBytes = messageDispatcher(plaintext) ?: return true
        val encryptedResponse = E2EEncryptionManager.encryptAESGCM(keys.keyAndroidToMac, responsePayload = responseBytes)

        // Send back as E2E_PAYLOAD JSON wrapper
        val respJson = JSONObject().apply {
            put("type", "E2E_PAYLOAD")
            put("ciphertext", Base64.getEncoder().encodeToString(encryptedResponse))
        }
        sendFunction(respJson.toString().toByteArray(Charsets.UTF_8))
        return true
    }

    private fun E2EEncryptionManager.Companion.encryptAESGCM(key: ByteArray, responsePayload: ByteArray): ByteArray {
        return encryptAESGCM(key, responsePayload, null)
    }
}
