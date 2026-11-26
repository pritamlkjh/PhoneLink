package com.phonelink.transport

import com.phonelink.crypto.KeyManager
import com.phonelink.identity.DeviceIdentityManager
import com.phonelink.identity.InMemorySharedPreferences
import com.phonelink.service.ConnectionForegroundService
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RelayUrlHelperTest {

    @Test
    fun testNormalizeHttpBaseUrlVariants() {
        assertEquals("http://172.24.250.225:8443", RelayUrlHelper.normalizeHttpBaseUrl("http://172.24.250.225:8443/"))
        assertEquals("https://relay.example.com", RelayUrlHelper.normalizeHttpBaseUrl("https://relay.example.com/ws/v1/connect?token=abc"))
        assertEquals("https://relay.example.com:8443", RelayUrlHelper.normalizeHttpBaseUrl("wss://relay.example.com:8443/ws/v1/connect"))
        assertEquals("http://192.168.1.5:8443", RelayUrlHelper.normalizeHttpBaseUrl("192.168.1.5:8443"))
        assertEquals("https://relay.example.com", RelayUrlHelper.normalizeHttpBaseUrl("relay.example.com"))
    }

    @Test
    fun testToWebSocketUrlAppendsEndpointAndToken() {
        assertEquals(
            "ws://172.24.250.225:8443/ws/v1/connect?token=tok_123",
            RelayUrlHelper.toWebSocketUrl("http://172.24.250.225:8443", "tok_123")
        )
        assertEquals(
            "wss://relay.example.com/ws/v1/connect?token=tok+a%2Fb",
            RelayUrlHelper.toWebSocketUrl("https://relay.example.com/", "tok a/b")
        )
    }

    @Test
    fun testUnifiedIdentityAndSigningKeyPairVerify() {
        val prefs = InMemorySharedPreferences()
        val storage = com.phonelink.storage.SecureStorage(prefs)
        val keyManager = KeyManager.fromStorage(storage)
        val identityManager = DeviceIdentityManager(prefs, keyManager.signer)

        val identity = identityManager.getOrCreateIdentity()
        assertTrue(identity.publicKeyEncoded.contentEquals(keyManager.signer.publicKeyEncoded))

        val sig = keyManager.signChallenge(byteArrayOf(1, 2), byteArrayOf(3, 4), 1000L)
        assertTrue(keyManager.verifyChallenge(byteArrayOf(1, 2), byteArrayOf(3, 4), 1000L, sig))
    }

    @Test
    fun testHandleControlMessageConsumesRelayFramesOnly() {
        val svc = ConnectionForegroundService()
        assertTrue(svc.handleControlMessage("""{"type":"PEER_STATUS","peer_device_id":"mac","is_online":true}"""))
        assertTrue(svc.handleControlMessage("""{"error":"paired peer is offline"}"""))
        assertFalse(svc.handleControlMessage("""{"type":"E2E_INIT","ephemeral_public_key":"abc"}"""))
        assertFalse(svc.handleControlMessage("not json"))
    }
}
