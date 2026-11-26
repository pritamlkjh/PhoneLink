package com.phonelink.security

import com.phonelink.actions.RemoteActionRegistry
import com.phonelink.camera.CameraAuthorizationGate
import com.phonelink.camera.CameraCaptureModule
import com.phonelink.camera.CameraCaptureModuleTest
import com.phonelink.files.FileOperationHandler
import com.phonelink.files.StorageAccessLayer
import com.phonelink.identity.InMemorySharedPreferences
import com.phonelink.mic.MicAuthorizationGate
import com.phonelink.mic.MicCaptureModule
import com.phonelink.mic.MicCaptureModuleTest
import com.phonelink.storage.SecureStorage
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File

/**
 * SEC-2: Security Validation & Penetration Testing Suite (Android component)
 * Validates against the ARCH-4 threat model and binding design constraints (DC-01 .. DC-07):
 * - T-08 / DC-02 / DC-03: Camera dual-gate cannot be bypassed via raw protocol messages
 * - T-09 / DC-07: Path traversal and filesystem scope cannot be bypassed
 * - DC-06: Build-time remote action allowlist cannot be bypassed by raw message actions
 * - DC-04 / DC-05: App must declare visible launcher activity and zero stealth modes
 */
class SecurityPenetrationTest {

    @get:Rule
    val tempFolder = TemporaryFolder()

    private lateinit var mockPrefs: InMemorySharedPreferences
    private lateinit var storage: SecureStorage
    private var osPermissionGranted = false
    private lateinit var authGate: CameraAuthorizationGate
    private lateinit var testCameraSource: CameraCaptureModuleTest.TestCameraSource
    private lateinit var testServiceController: CameraCaptureModuleTest.TestServiceController
    private lateinit var cameraModule: CameraCaptureModule
    private lateinit var micAuthGate: MicAuthorizationGate
    private lateinit var testMicSource: MicCaptureModuleTest.TestMicSource
    private lateinit var testMicServiceController: MicCaptureModuleTest.TestServiceController
    private lateinit var micModule: MicCaptureModule

    private lateinit var scopedRootDir: File
    private lateinit var storageLayer: StorageAccessLayer
    private lateinit var fileHandler: FileOperationHandler
    private lateinit var actionRegistry: RemoteActionRegistry

    @Before
    fun setUp() {
        mockPrefs = InMemorySharedPreferences()
        storage = SecureStorage(mockPrefs)
        osPermissionGranted = false

        authGate = CameraAuthorizationGate(
            secureStorage = storage,
            permissionChecker = { osPermissionGranted }
        )

        testCameraSource = CameraCaptureModuleTest.TestCameraSource()
        testServiceController = CameraCaptureModuleTest.TestServiceController()

        cameraModule = CameraCaptureModule(
            cameraAuthGate = authGate,
            cameraSource = testCameraSource,
            serviceController = testServiceController
        )

        micAuthGate = MicAuthorizationGate(
            secureStorage = storage,
            permissionChecker = { osPermissionGranted }
        )
        testMicSource = MicCaptureModuleTest.TestMicSource()
        testMicServiceController = MicCaptureModuleTest.TestServiceController()
        micModule = MicCaptureModule(
            micAuthGate = micAuthGate,
            micSource = testMicSource,
            serviceController = testMicServiceController
        )

        scopedRootDir = tempFolder.newFolder("PhoneLinkDownload")
        storageLayer = StorageAccessLayer(scopedRootDir)
        fileHandler = FileOperationHandler(storageLayer)
        actionRegistry = RemoteActionRegistry()
    }

    // --- PEN-TEST 1: T-08 / DC-02 Camera Dual-Gate Raw Protocol Bypass Attempts ---

    @Test
    fun testRawCameraStartRejectedWhenUserToggleDisabled() {
        // OS permission is granted, but device owner toggle is OFF (Gate 2 OFF)
        osPermissionGranted = true
        authGate.setInAppToggle(false)

        val rawPayload = JSONObject().apply {
            put("camera_start_req", JSONObject().apply {
                put("session_id", "pen-cam-01")
                put("lens", "LENS_BACK")
                put("target_fps", 5)
                put("bypass_auth", true) // Attacker attempts fake parameter override
            })
        }.toString().toByteArray(Charsets.UTF_8)

        val responseBytes = cameraModule.processApplicationMessage(rawPayload)
        assertNotNull("Must return response", responseBytes)

        val responseJson = JSONObject(String(responseBytes!!, Charsets.UTF_8))
        val startResp = responseJson.getJSONObject("camera_start_resp")
        assertEquals(
            "Must reject with STATUS_CAMERA_TOGGLE_DISABLED",
            CameraCaptureModule.STATUS_CAMERA_TOGGLE_DISABLED,
            startResp.getString("status")
        )
        assertFalse("Camera hardware must NOT be capturing", testCameraSource.capturing.get())
        assertFalse("Module must not report active capturing", cameraModule.isCapturing())
    }

    @Test
    fun testRawCameraStartRejectedWhenOsPermissionDenied() {
        // In-app toggle is ON, but OS permission is DENIED (Gate 1 OFF)
        osPermissionGranted = false
        authGate.setInAppToggle(true)

        val rawPayload = JSONObject().apply {
            put("camera_start_req", JSONObject().apply {
                put("session_id", "pen-cam-02")
                put("lens", "LENS_FRONT")
                put("target_fps", 2)
            })
        }.toString().toByteArray(Charsets.UTF_8)

        val responseBytes = cameraModule.processApplicationMessage(rawPayload)
        assertNotNull("Must return response", responseBytes)

        val responseJson = JSONObject(String(responseBytes!!, Charsets.UTF_8))
        val startResp = responseJson.getJSONObject("camera_start_resp")
        assertEquals(
            "Must reject with STATUS_CAMERA_PERMISSION_DENIED",
            CameraCaptureModule.STATUS_CAMERA_PERMISSION_DENIED,
            startResp.getString("status")
        )
        assertFalse("Camera hardware must NOT be capturing", testCameraSource.capturing.get())
        assertFalse("Module must not report active capturing", cameraModule.isCapturing())
    }

    @Test
    fun testRawMicStartRejectedWhenUserToggleDisabled() {
        osPermissionGranted = true
        micAuthGate.setInAppToggle(false)

        val rawPayload = JSONObject().apply {
            put("mic_start_req", JSONObject().apply {
                put("session_id", "pen-mic-01")
                put("sample_rate_hz", 16000)
                put("bypass_auth", true)
            })
        }.toString().toByteArray(Charsets.UTF_8)

        val responseBytes = micModule.processApplicationMessage(rawPayload)
        assertNotNull("Must return response", responseBytes)

        val startResp = JSONObject(String(responseBytes!!, Charsets.UTF_8)).getJSONObject("mic_start_resp")
        assertEquals(
            "Must reject with STATUS_MIC_TOGGLE_DISABLED",
            MicCaptureModule.STATUS_MIC_TOGGLE_DISABLED,
            startResp.getString("status")
        )
        assertFalse("Microphone hardware must NOT be capturing", testMicSource.capturing.get())
        assertFalse("Module must not report active capturing", micModule.isCapturing())
    }

    @Test
    fun testRawMicStartRejectedWhenOsPermissionDenied() {
        osPermissionGranted = false
        micAuthGate.setInAppToggle(true)

        val rawPayload = JSONObject().apply {
            put("mic_start_req", JSONObject().apply {
                put("session_id", "pen-mic-02")
                put("sample_rate_hz", 16000)
            })
        }.toString().toByteArray(Charsets.UTF_8)

        val responseBytes = micModule.processApplicationMessage(rawPayload)
        assertNotNull("Must return response", responseBytes)

        val startResp = JSONObject(String(responseBytes!!, Charsets.UTF_8)).getJSONObject("mic_start_resp")
        assertEquals(
            "Must reject with STATUS_MIC_PERMISSION_DENIED",
            MicCaptureModule.STATUS_MIC_PERMISSION_DENIED,
            startResp.getString("status")
        )
        assertFalse("Microphone hardware must NOT be capturing", testMicSource.capturing.get())
        assertFalse("Module must not report active capturing", micModule.isCapturing())
    }

    // --- PEN-TEST 2: T-09 / DC-07 File System Scope & Path Traversal Bypass Attempts ---

    @Test
    fun testRawFileDownloadPathTraversalRejected() {
        val traversalAttacks = listOf(
            "../../../../etc/shadow",
            "../../../data/data/com.phonelink/databases/keys.db",
            "report.pdf/../../../system/build.prop",
            "/data/data/com.phonelink/shared_prefs/secret.xml"
        )

        for (badPath in traversalAttacks) {
            val rawPayload = JSONObject().apply {
                put("file_download_req", JSONObject().apply {
                    put("transfer_id", "pen-dl-01")
                    put("file_path", badPath)
                })
            }.toString().toByteArray(Charsets.UTF_8)

            val responseBytes = fileHandler.processApplicationMessage(rawPayload)
            assertNotNull("Must return rejection response for $badPath", responseBytes)

            val responseJson = JSONObject(String(responseBytes!!, Charsets.UTF_8))
            val dlResp = responseJson.getJSONObject("file_download_init_resp")
            val status = dlResp.getString("status")
            assertEquals(
                "Path traversal '$badPath' must be rejected with STATUS_STORAGE_ACCESS_DENIED",
                FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED,
                status
            )
        }
    }

    @Test
    fun testRawFileUploadPathTraversalRejected() {
        val rawPayload = JSONObject().apply {
            put("file_upload_req", JSONObject().apply {
                put("transfer_id", "pen-upload-01")
                put("destination_path", "../../../data/system")
                put("file_name", "malicious.apk")
                put("total_size_bytes", 100L)
                put("sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
            })
        }.toString().toByteArray(Charsets.UTF_8)

        val responseBytes = fileHandler.processApplicationMessage(rawPayload)
        assertNotNull("Must return rejection response for upload traversal", responseBytes)

        val responseJson = JSONObject(String(responseBytes!!, Charsets.UTF_8))
        val upResp = responseJson.getJSONObject("file_upload_init_resp")
        val status = upResp.getString("status")
        assertEquals(
            "Upload path traversal must be rejected with STATUS_STORAGE_ACCESS_DENIED",
            FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED,
            status
        )
    }

    // --- PEN-TEST 3: DC-06 Remote Action Build-Time Allowlist Bypass Attempts ---

    @Test
    fun testArbitraryRemoteActionExecutionRejected() {
        val dangerousActions = listOf(
            "sh",
            "bash",
            "exec",
            "rm -rf /",
            "install_apk",
            "reboot",
            "read_sms",
            "dump_contacts",
            "eval"
        )

        for (action in dangerousActions) {
            val rawPayload = JSONObject().apply {
                put("action_request", JSONObject().apply {
                    put("action", action)
                    put("request_id", "pen-act-01")
                })
            }.toString().toByteArray(Charsets.UTF_8)

            val responseBytes = actionRegistry.processApplicationMessage(rawPayload)
            assertNotNull("Must return rejection response for $action", responseBytes)

            val responseJson = JSONObject(String(responseBytes!!, Charsets.UTF_8))
            val errResp = responseJson.getJSONObject("error")
            assertEquals(
                "Action '$action' must be rejected with STATUS_ACTION_NOT_PERMITTED",
                RemoteActionRegistry.STATUS_ACTION_NOT_PERMITTED,
                errResp.getString("code")
            )
        }
    }

    // --- PEN-TEST 4: DC-01 / DC-04 / DC-05 Anti-Stealth & Visible App Manifest Audit ---

    @Test
    fun testManifestDeclaresLauncherActivityAndZeroStealthModes() {
        val manifestFile = File("src/main/AndroidManifest.xml")
        assertTrue("AndroidManifest.xml must exist", manifestFile.exists())
        val content = manifestFile.readText()

        // 1. DC-05: App launcher icon in app drawer
        assertTrue(
            "Manifest must declare android.intent.action.MAIN",
            content.contains("android.intent.action.MAIN")
        )
        assertTrue(
            "Manifest must declare android.intent.category.LAUNCHER",
            content.contains("android.intent.category.LAUNCHER")
        )

        // 2. DC-01: Foreground service declared with camera and dataSync types
        assertTrue(
            "ConnectionForegroundService must declare foregroundServiceType with camera and dataSync",
            content.contains("android:foregroundServiceType") &&
                    content.contains("camera") &&
                    content.contains("dataSync")
        )

        // 3. DC-04: Zero hidden or stealth features
        assertFalse(
            "Manifest must NOT request hide app / device admin stealth permissions",
            content.contains("BIND_DEVICE_ADMIN")
        )
    }
}
