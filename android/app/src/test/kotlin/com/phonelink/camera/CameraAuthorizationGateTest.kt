package com.phonelink.camera

import com.phonelink.storage.SecureStorage
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class CameraAuthorizationGateTest {

    private class MockSharedPreferences : android.content.SharedPreferences {
        private val data = mutableMapOf<String, Any?>()

        override fun getAll(): MutableMap<String, *> = data
        override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
        override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = null
        override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
        override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
        override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
        override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
        override fun contains(key: String?): Boolean = data.containsKey(key)
        override fun edit(): android.content.SharedPreferences.Editor = MockEditor(data)
        override fun registerOnSharedPreferenceChangeListener(listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}
        override fun unregisterOnSharedPreferenceChangeListener(listener: android.content.SharedPreferences.OnSharedPreferenceChangeListener?) {}

        private class MockEditor(private val data: MutableMap<String, Any?>) : android.content.SharedPreferences.Editor {
            private val temp = mutableMapOf<String, Any?>()
            private val removes = mutableSetOf<String>()
            private var clear = false

            override fun putString(key: String?, value: String?): android.content.SharedPreferences.Editor {
                if (key != null) temp[key] = value
                return this
            }
            override fun putStringSet(key: String?, values: MutableSet<String>?): android.content.SharedPreferences.Editor = this
            override fun putInt(key: String?, value: Int): android.content.SharedPreferences.Editor = this
            override fun putLong(key: String?, value: Long): android.content.SharedPreferences.Editor = this
            override fun putFloat(key: String?, value: Float): android.content.SharedPreferences.Editor = this
            override fun putBoolean(key: String?, value: Boolean): android.content.SharedPreferences.Editor = this
            override fun remove(key: String?): android.content.SharedPreferences.Editor {
                if (key != null) removes.add(key)
                return this
            }
            override fun clear(): android.content.SharedPreferences.Editor {
                clear = true
                return this
            }
            override fun commit(): Boolean {
                apply()
                return true
            }
            override fun apply() {
                if (clear) data.clear()
                removes.forEach { data.remove(it) }
                data.putAll(temp)
            }
        }
    }

    private lateinit var mockPrefs: MockSharedPreferences
    private lateinit var secureStorage: SecureStorage

    @Before
    fun setUp() {
        mockPrefs = MockSharedPreferences()
        secureStorage = SecureStorage(mockPrefs)
    }

    @Test
    fun testFreshInstallDefaultsToOff() {
        val gate = CameraAuthorizationGate(secureStorage) { false }
        assertFalse(gate.isInAppToggleEnabled(), "Fresh install must default in-app camera toggle to OFF")
    }

    @Test
    fun testBothGatesDenied() {
        val gate = CameraAuthorizationGate(secureStorage) { false }
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = false)

        assertFalse(decision.isAuthorized)
        assertEquals(CameraAuthorizationGate.AuthorizationStatus.DENIED_BOTH_GATES_FAILED, decision.status)
        assertFalse(gate.isRemoteActivationPermitted(osPermissionOverride = false))
    }

    @Test
    fun testOsGrantedButInAppToggleOff() {
        val gate = CameraAuthorizationGate(secureStorage) { true }
        // OS permission is granted (true), but in-app toggle is off (default false)
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = true)

        assertFalse(decision.isAuthorized, "Camera must NOT activate remotely when in-app toggle is OFF")
        assertEquals(CameraAuthorizationGate.AuthorizationStatus.DENIED_IN_APP_TOGGLE_DISABLED, decision.status)
        assertFalse(gate.isRemoteActivationPermitted(osPermissionOverride = true))
    }

    @Test
    fun testInAppToggleOnButOsDenied() {
        val gate = CameraAuthorizationGate(secureStorage) { false }
        gate.setInAppToggle(true)
        assertTrue(gate.isInAppToggleEnabled())

        // OS permission is denied (false), but toggle is on (true)
        val decision = gate.evaluateRemoteActivation(osPermissionOverride = false)

        assertFalse(decision.isAuthorized, "Camera must NOT activate when OS permission is denied")
        assertEquals(CameraAuthorizationGate.AuthorizationStatus.DENIED_OS_PERMISSION_MISSING, decision.status)
        assertFalse(gate.isRemoteActivationPermitted(osPermissionOverride = false))
    }

    @Test
    fun testBothGatesSatisfiedAuthorizesCamera() {
        val gate = CameraAuthorizationGate(secureStorage) { true }
        gate.setInAppToggle(true)

        val decision = gate.evaluateRemoteActivation(osPermissionOverride = true)

        assertTrue(decision.isAuthorized, "Camera MUST be authorized when both gates are satisfied")
        assertEquals(CameraAuthorizationGate.AuthorizationStatus.AUTHORIZED, decision.status)
        assertTrue(gate.isRemoteActivationPermitted(osPermissionOverride = true))
    }

    @Test
    fun testToggleStatePersists() {
        val gate = CameraAuthorizationGate(secureStorage) { true }
        assertFalse(gate.isInAppToggleEnabled())

        gate.setInAppToggle(true)
        assertTrue(gate.isInAppToggleEnabled())

        gate.setInAppToggle(false)
        assertFalse(gate.isInAppToggleEnabled())
    }
}
