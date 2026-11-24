package com.phonelink.crypto

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class KeyManagerTest {

    @Test
    fun testSignAndVerifyChallengeRoundTrip() {
        val manager = KeyManager.createSoftware()
        val serverNonce = byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val clientNonce = byteArrayOf(9, 10, 11, 12, 13, 14, 15, 16)
        val timestamp = 1774422000000L

        val signature = manager.signChallenge(serverNonce, clientNonce, timestamp)
        assertNotNull(signature)
        assertTrue(signature.isNotEmpty())

        val isValid = manager.verifyChallenge(serverNonce, clientNonce, timestamp, signature)
        assertTrue(isValid, "Valid signature must verify successfully")
    }

    @Test
    fun testCorruptedDataRejection() {
        val manager = KeyManager.createSoftware()
        val serverNonce = byteArrayOf(1, 2, 3, 4)
        val clientNonce = byteArrayOf(5, 6, 7, 8)
        val timestamp = 1774422000000L

        val signature = manager.signChallenge(serverNonce, clientNonce, timestamp)

        // Alter timestamp
        val wrongTimestamp = timestamp + 1000
        val isValid = manager.verifyChallenge(serverNonce, clientNonce, wrongTimestamp, signature)
        assertFalse(isValid, "Altered timestamp must cause verification failure")

        // Alter server nonce
        val corruptedNonce = byteArrayOf(99, 2, 3, 4)
        val isCorruptedValid = manager.verifyChallenge(corruptedNonce, clientNonce, timestamp, signature)
        assertFalse(isCorruptedValid, "Altered nonce must cause verification failure")
    }

    @Test
    fun testWrongKeyRejection() {
        val manager1 = KeyManager.createSoftware()
        val manager2 = KeyManager.createSoftware()

        val serverNonce = byteArrayOf(1, 2, 3, 4)
        val clientNonce = byteArrayOf(5, 6, 7, 8)
        val timestamp = 1774422000000L

        val signature1 = manager1.signChallenge(serverNonce, clientNonce, timestamp)

        // Verify with manager2's different key
        val isValid = manager2.verifyChallenge(serverNonce, clientNonce, timestamp, signature1)
        assertFalse(isValid, "Signature from key 1 must not verify with key 2")
    }

    @Test
    fun testPublicKeyExport() {
        val manager = KeyManager.createSoftware()
        val base64Key = manager.getPublicKeyBase64()
        assertNotNull(base64Key)
        assertTrue(base64Key.isNotEmpty())
    }
}
