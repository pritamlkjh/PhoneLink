package com.phonelink.crypto

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class E2EEncryptionManagerTest {

    @Test
    fun testEphemeralKeyPairGeneration() {
        val manager = E2EEncryptionManager()
        assertNotNull(manager.ephemeralKeyPair.public)
        assertNotNull(manager.ephemeralKeyPair.private)
        assertTrue(manager.getPublicKeyEncoded().isNotEmpty())
    }

    @Test
    fun testKeyDerivationAndEncryptionRoundTrip() {
        val peerMac = E2EEncryptionManager()
        val peerAndroid = E2EEncryptionManager()

        val salt = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val macKeys = peerMac.deriveSessionKeys(peerAndroid.ephemeralKeyPair.public, salt)
        val androidKeys = peerAndroid.deriveSessionKeys(peerMac.ephemeralKeyPair.public, salt)

        // Mac -> Android key must match on both sides
        assertTrue(macKeys.keyMacToAndroid.contentEquals(androidKeys.keyMacToAndroid), "K_M2A must be identical")
        assertTrue(macKeys.keyAndroidToMac.contentEquals(androidKeys.keyAndroidToMac), "K_A2M must be identical")

        // 1. Mac sends encrypted message to Android
        val pingMessage = "PHONELINK_E2E_PING_VERIFICATION_PAYLOAD_12345"
        val aad = "session-seq-1".toByteArray(Charsets.UTF_8)
        val ciphertext = E2EEncryptionManager.encryptAESGCM(
            macKeys.keyMacToAndroid,
            pingMessage.toByteArray(Charsets.UTF_8),
            aad
        )

        // Ensure ciphertext does NOT contain plaintext
        val ciphertextString = String(ciphertext, Charsets.ISO_8859_1)
        assertTrue(!ciphertextString.contains("PING"), "Ciphertext must never expose plaintext")

        // Android decrypts
        val decryptedBytes = E2EEncryptionManager.decryptAESGCM(
            androidKeys.keyMacToAndroid,
            ciphertext,
            aad
        )
        val decryptedMessage = String(decryptedBytes, Charsets.UTF_8)
        assertEquals(pingMessage, decryptedMessage)

        // 2. Android sends encrypted reply to Mac
        val pongMessage = "PHONELINK_E2E_PONG_VERIFICATION_PAYLOAD_67890"
        val replyCiphertext = E2EEncryptionManager.encryptAESGCM(
            androidKeys.keyAndroidToMac,
            pongMessage.toByteArray(Charsets.UTF_8),
            aad
        )

        val decryptedReplyBytes = E2EEncryptionManager.decryptAESGCM(
            macKeys.keyAndroidToMac,
            replyCiphertext,
            aad
        )
        val decryptedReply = String(decryptedReplyBytes, Charsets.UTF_8)
        assertEquals(pongMessage, decryptedReply)
    }

    @Test
    fun testTamperedCiphertextRejection() {
        val key = ByteArray(32) { 42 }
        val plaintext = "Sensitive Data".toByteArray(Charsets.UTF_8)
        val ciphertext = E2EEncryptionManager.encryptAESGCM(key, plaintext)

        // Tamper with ciphertext byte
        ciphertext[ciphertext.size - 1] = (ciphertext[ciphertext.size - 1].toInt() xor 0xFF).toByte()

        assertFailsWith<Exception> {
            E2EEncryptionManager.decryptAESGCM(key, ciphertext)
        }
    }
}
