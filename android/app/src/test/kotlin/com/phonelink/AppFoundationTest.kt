package com.phonelink

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class AppFoundationTest {
    @Test
    fun testAppVersion() {
        assertEquals("1.0.0", PhoneLinkApp.VERSION)
    }

    @Test
    fun testNotificationChannelId() {
        assertNotNull(PhoneLinkApp.NOTIFICATION_CHANNEL_ID)
        assertEquals("phonelink_connection_channel", PhoneLinkApp.NOTIFICATION_CHANNEL_ID)
    }
}
