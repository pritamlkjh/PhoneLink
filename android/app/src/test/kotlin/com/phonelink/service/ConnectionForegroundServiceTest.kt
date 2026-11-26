package com.phonelink.service

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ConnectionForegroundServiceTest {

    @Test
    fun testServiceConstants() {
        assertEquals("phonelink_connection_channel", ConnectionForegroundService.CHANNEL_ID)
        assertEquals(1001, ConnectionForegroundService.NOTIFICATION_ID)
        assertEquals("com.phonelink.service.ACTION_START", ConnectionForegroundService.ACTION_START)
        assertEquals("com.phonelink.service.ACTION_STOP", ConnectionForegroundService.ACTION_STOP)
    }

    @Test
    fun testForegroundServiceLifecycleStructure() {
        // Verifies class is properly constructed and inherits Service
        val serviceClass = ConnectionForegroundService::class.java
        assertTrue(android.app.Service::class.java.isAssignableFrom(serviceClass))
        assertNotNull(serviceClass.constructors)
    }

    @Test
    fun testHandleControlMessagePeerStatus() {
        var observedPeerId = ""
        var observedOnline: Boolean? = null

        ConnectionForegroundService.peerStatusListener = { peerId, isOnline ->
            observedPeerId = peerId
            observedOnline = isOnline
        }

        val service = ConnectionForegroundService()

        // 1. Peer comes online
        val onlineJson = "{\"type\":\"PEER_STATUS\",\"peer_device_id\":\"mac-peer-123\",\"is_online\":true,\"timestamp\":123456}"
        service.handleControlMessage(onlineJson)

        assertEquals("mac-peer-123", observedPeerId)
        assertEquals(true, observedOnline)

        // 2. Peer goes offline
        val offlineJson = "{\"type\":\"PEER_STATUS\",\"peer_device_id\":\"mac-peer-123\",\"is_online\":false,\"timestamp\":123460}"
        service.handleControlMessage(offlineJson)

        assertEquals("mac-peer-123", observedPeerId)
        assertEquals(false, observedOnline)

        // Cleanup
        ConnectionForegroundService.peerStatusListener = null
    }

    @Test
    fun testForegroundNotificationTextAndCapabilityBitmask() {
        assertEquals(
            "Connected to VPS relay",
            ConnectionForegroundService.computeForegroundNotificationText(cameraActive = false, micActive = false)
        )
        assertEquals(
            "PhoneLink: Camera streaming active",
            ConnectionForegroundService.computeForegroundNotificationText(cameraActive = true, micActive = false)
        )
        assertEquals(
            "PhoneLink: Microphone streaming active",
            ConnectionForegroundService.computeForegroundNotificationText(cameraActive = false, micActive = true)
        )
        assertEquals(
            "PhoneLink: Camera & Microphone streaming",
            ConnectionForegroundService.computeForegroundNotificationText(cameraActive = true, micActive = true)
        )

        val base = ConnectionForegroundService.computeForegroundServiceTypes(cameraActive = false, micActive = false)
        val withCam = ConnectionForegroundService.computeForegroundServiceTypes(cameraActive = true, micActive = false)
        val withMic = ConnectionForegroundService.computeForegroundServiceTypes(cameraActive = false, micActive = true)
        val withBoth = ConnectionForegroundService.computeForegroundServiceTypes(cameraActive = true, micActive = true)
        assertTrue(withCam != base && withMic != base && withBoth != withCam && withBoth != withMic)
    }
}
