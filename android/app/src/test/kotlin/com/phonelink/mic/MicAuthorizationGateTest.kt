package com.phonelink.mic

import com.phonelink.identity.InMemorySharedPreferences
import com.phonelink.storage.SecureStorage
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MicAuthorizationGateTest {

    private lateinit var secureStorage: SecureStorage

    @Before
    fun setUp() {
        secureStorage = SecureStorage(InMemorySharedPreferences())
    }

    @Test
    fun testFreshInstallDefaultsToOff() {
        val gate = MicAuthorizationGate(secureStorage) { false }
        assertFalse(gate.isInAppToggleEnabled(), "Fresh install must default in-app mic toggle to OFF")
    }

    @Test
    fun testBothGatesDenied() {
        val gate = MicAuthorizationGate(secureStorage) { false }
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = false)
        assertFalse(decision.isAuthorized)
        assertEquals(MicAuthorizationGate.AuthorizationStatus.DENIED_BOTH_GATES_FAILED, decision.status)
    }

    @Test
    fun testOsGrantedButToggleOffRejected() {
        val gate = MicAuthorizationGate(secureStorage) { true }
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = true)
        assertFalse(decision.isAuthorized)
        assertEquals(MicAuthorizationGate.AuthorizationStatus.DENIED_IN_APP_TOGGLE_DISABLED, decision.status)
    }

    @Test
    fun testToggleOnButOsDeniedRejected() {
        val gate = MicAuthorizationGate(secureStorage) { false }
        gate.setInAppToggle(true)
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = false)
        assertFalse(decision.isAuthorized)
        assertEquals(MicAuthorizationGate.AuthorizationStatus.DENIED_OS_PERMISSION_MISSING, decision.status)
    }

    @Test
    fun testBothGatesSatisfiedAuthorizesMic() {
        val gate = MicAuthorizationGate(secureStorage) { true }
        gate.setInAppToggle(true)
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = true)
        assertTrue(decision.isAuthorized)
        assertEquals(MicAuthorizationGate.AuthorizationStatus.AUTHORIZED, decision.status)
    }
}
