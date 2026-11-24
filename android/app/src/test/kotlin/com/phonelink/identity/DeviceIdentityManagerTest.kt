package com.phonelink.identity

import android.content.SharedPreferences
import org.junit.Before
import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DeviceIdentityManagerTest {

    private lateinit var mockPrefs: InMemorySharedPreferences

    @Before
    fun setUp() {
        mockPrefs = InMemorySharedPreferences()
    }

    @Test
    fun testIdentityCreationAndPersistence() {
        val manager1 = DeviceIdentityManager(mockPrefs)
        val id1 = manager1.getOrCreateIdentity()

        assertNotNull(id1.deviceId)
        assertEquals(64, id1.deviceId.length)
        assertTrue(id1.publicKeyEncoded.isNotEmpty())
        assertTrue(id1.privateKeyEncoded.isNotEmpty())

        // Re-instantiate manager with same preferences (process restart simulation)
        val manager2 = DeviceIdentityManager(mockPrefs)
        val id2 = manager2.getOrCreateIdentity()

        assertEquals(id1.deviceId, id2.deviceId, "Device ID must persist across process restarts")
        assertTrue(id1.publicKeyEncoded.contentEquals(id2.publicKeyEncoded), "Public key must match")
        assertTrue(id1.privateKeyEncoded.contentEquals(id2.privateKeyEncoded), "Private key must match")
    }

    @Test
    fun testReinstallProducesNewIdentity() {
        val manager = DeviceIdentityManager(mockPrefs)
        val originalId = manager.getOrCreateIdentity()

        // Simulate reinstall
        manager.clearIdentity()

        val newId = manager.getOrCreateIdentity()
        assertNotEquals(originalId.deviceId, newId.deviceId, "Reinstall must produce a fresh device identity")
        assertTrue(!originalId.publicKeyEncoded.contentEquals(newId.publicKeyEncoded), "New public key must differ")
    }

    @Test
    fun testHexConversion() {
        val testBytes = byteArrayOf(0x00, 0x01, 0x0F, 0x7F, -0x80, -0x01)
        val hex = DeviceIdentityManager.bytesToHex(testBytes)
        assertEquals("00010f7f80ff", hex)
        val roundtrip = DeviceIdentityManager.hexToBytes(hex)
        assertTrue(testBytes.contentEquals(roundtrip))
    }
}

/**
 * In-memory SharedPreferences for clean unit testing without Android runtime.
 */
class InMemorySharedPreferences : SharedPreferences {
    private val data = mutableMapOf<String, Any>()

    override fun getAll(): MutableMap<String, *> = data
    override fun getString(key: String?, defValue: String?): String? = data[key] as? String ?: defValue
    override fun getStringSet(key: String?, defValues: MutableSet<String>?): MutableSet<String>? = defValues
    override fun getInt(key: String?, defValue: Int): Int = data[key] as? Int ?: defValue
    override fun getLong(key: String?, defValue: Long): Long = data[key] as? Long ?: defValue
    override fun getFloat(key: String?, defValue: Float): Float = data[key] as? Float ?: defValue
    override fun getBoolean(key: String?, defValue: Boolean): Boolean = data[key] as? Boolean ?: defValue
    override fun contains(key: String?): Boolean = data.containsKey(key)
    override fun edit(): SharedPreferences.Editor = EditorImpl(this)
    override fun registerOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(listener: SharedPreferences.OnSharedPreferenceChangeListener?) {}

    class EditorImpl(private val parent: InMemorySharedPreferences) : SharedPreferences.Editor {
        private val temp = mutableMapOf<String, Any?>()
        private var clear = false

        override fun putString(key: String?, value: String?): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putStringSet(key: String?, values: MutableSet<String>?): SharedPreferences.Editor = this
        override fun putInt(key: String?, value: Int): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putLong(key: String?, value: Long): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putFloat(key: String?, value: Float): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun putBoolean(key: String?, value: Boolean): SharedPreferences.Editor {
            if (key != null) temp[key] = value
            return this
        }
        override fun remove(key: String?): SharedPreferences.Editor {
            if (key != null) temp[key] = null
            return this
        }
        override fun clear(): SharedPreferences.Editor {
            clear = true
            return this
        }
        override fun commit(): Boolean {
            apply()
            return true
        }
        override fun apply() {
            if (clear) parent.data.clear()
            for ((k, v) in temp) {
                if (v == null) parent.data.remove(k)
                else parent.data[k] = v
            }
        }
    }
}
