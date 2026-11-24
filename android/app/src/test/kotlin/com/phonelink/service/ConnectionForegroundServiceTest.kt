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
}
