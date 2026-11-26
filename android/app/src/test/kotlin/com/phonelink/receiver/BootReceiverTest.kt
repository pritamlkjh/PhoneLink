package com.phonelink.receiver

import android.content.BroadcastReceiver
import android.content.Intent
import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class BootReceiverTest {

    @Test
    fun testBootReceiverConstants() {
        assertEquals("phonelink_boot_recovery", BootReceiver.BOOT_RECOVERY_CHANNEL_ID)
        assertEquals(1002, BootReceiver.BOOT_PROMPT_NOTIFICATION_ID)

        assertTrue(BootReceiver.SUPPORTED_BOOT_ACTIONS.contains(Intent.ACTION_BOOT_COMPLETED))
        assertTrue(BootReceiver.SUPPORTED_BOOT_ACTIONS.contains("android.intent.action.QUICKBOOT_POWERON"))
        assertFalse(BootReceiver.SUPPORTED_BOOT_ACTIONS.contains("com.htc.intent.action.QUICKBOOT_POWERON"))
    }

    @Test
    fun testBootReceiverClassStructure() {
        val receiverClass = BootReceiver::class.java
        assertTrue(BroadcastReceiver::class.java.isAssignableFrom(receiverClass))
        assertNotNull(receiverClass.constructors)
    }

    @Test
    fun testManifestBootDeclarationsAndSecurityInvariants() {
        val manifestCandidates = listOf(
            File("src/main/AndroidManifest.xml"),
            File("app/src/main/AndroidManifest.xml"),
            File("android/app/src/main/AndroidManifest.xml")
        )
        val manifestFile = manifestCandidates.firstOrNull { it.exists() }
        assertNotNull(manifestFile, "AndroidManifest.xml not found")

        val manifestContent = manifestFile.readText()

        // 1. Minimum necessary permission requested
        assertTrue(
            manifestContent.contains("<uses-permission android:name=\"android.permission.RECEIVE_BOOT_COMPLETED\" />"),
            "Manifest must declare RECEIVE_BOOT_COMPLETED"
        )

        // 2. Explicit receiver declaration with exported=true
        assertTrue(
            manifestContent.contains("android:name=\".receiver.BootReceiver\""),
            "Manifest must declare BootReceiver"
        )
        assertTrue(
            manifestContent.contains("android:exported=\"true\""),
            "BootReceiver must be exported to receive system boot broadcasts"
        )

        // 3. Clean BOOT_COMPLETED filter (without Play-Protect heuristic triggers)
        assertTrue(
            manifestContent.contains("<action android:name=\"android.intent.action.BOOT_COMPLETED\" />"),
            "Manifest must filter for BOOT_COMPLETED"
        )

        // 4. Anti-stalkerware invariants
        assertFalse(
            manifestContent.contains("BIND_DEVICE_ADMIN"),
            "Must NOT request BIND_DEVICE_ADMIN"
        )
        assertFalse(
            manifestContent.contains("android:persistent=\"true\""),
            "Must NOT declare persistent system flag"
        )
    }
}
