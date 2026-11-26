package com.phonelink.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.PowerManager
import android.provider.Settings
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.switchmaterial.SwitchMaterial
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textview.MaterialTextView
import com.phonelink.PhoneLinkApp
import com.phonelink.R
import com.phonelink.auth.AuthClient
import com.phonelink.crypto.KeyManager
import com.phonelink.identity.DeviceIdentityManager
import com.phonelink.service.ConnectionForegroundService
import com.phonelink.storage.SecureStorage
import com.phonelink.transport.RelayUrlHelper
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQ_CODE_NOTIFICATIONS = 101
        private const val REQ_CODE_CAMERA = 102
        private const val REQ_CODE_MIC = 103
    }

    private val executor = Executors.newSingleThreadExecutor()

    private lateinit var secureStorage: SecureStorage
    private lateinit var identityManager: DeviceIdentityManager
    private lateinit var keyManager: KeyManager
    private lateinit var authClient: AuthClient

    private lateinit var tvDeviceId: android.widget.TextView
    private lateinit var tvStatus: android.widget.TextView
    private lateinit var etRelayUrl: TextInputEditText
    private lateinit var etPairingCode: TextInputEditText
    private lateinit var btnConnectPair: MaterialButton
    private lateinit var btnUnpair: MaterialButton
    private lateinit var switchCamera: SwitchMaterial
    private lateinit var switchMic: SwitchMaterial
    private lateinit var switchBoot: SwitchMaterial
    private lateinit var btnPermNotification: MaterialButton
    private lateinit var btnPermCamera: MaterialButton
    private lateinit var btnPermMic: MaterialButton
    private lateinit var btnPermBattery: MaterialButton
    private lateinit var btnSelectFolder: MaterialButton

    private val openFolderLauncher = registerForActivityResult(ActivityResultContracts.OpenDocumentTree()) { uri ->
        if (uri != null) {
            try {
                val flags = Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION
                contentResolver.takePersistableUriPermission(uri, flags)
                secureStorage.setScopedTreeUri(uri.toString())
                updateUIState()
                Toast.makeText(this, "Shared folder updated", Toast.LENGTH_SHORT).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Failed to persist folder access: ${e.message}", Toast.LENGTH_LONG).show()
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize core dependencies (unified identity & signing keypair)
        secureStorage = SecureStorage.fromContext(this)
        keyManager = KeyManager.fromContext(this, secureStorage)
        identityManager = DeviceIdentityManager.fromContext(this, keyManager)
        authClient = AuthClient(secureStorage = secureStorage)

        bindViews()
        setupListeners()
        updateUIState()
        ensureServiceRunningIfPaired()
    }

    override fun onResume() {
        super.onResume()
        updateUIState()
        ensureServiceRunningIfPaired()
    }

    private fun ensureServiceRunningIfPaired() {
        if (!secureStorage.isPaired()) return
        val normalizedRelay = RelayUrlHelper.normalizeHttpBaseUrl(secureStorage.getRelayUrl())
        if (normalizedRelay.isEmpty()) return
        try {
            ConnectionForegroundService.start(this)
        } catch (_: Throwable) {
            // Foreground service may require user interaction on locked/restricted states
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        authClient.cancelAll()
        executor.shutdownNow()
    }

    private fun bindViews() {
        tvDeviceId = findViewById(R.id.tvDeviceId)
        tvStatus = findViewById(R.id.tvStatus)
        etRelayUrl = findViewById(R.id.etRelayUrl)
        etPairingCode = findViewById(R.id.etPairingCode)
        btnConnectPair = findViewById(R.id.btnConnectPair)
        btnUnpair = findViewById(R.id.btnUnpair)
        switchCamera = findViewById(R.id.switchCamera)
        switchMic = findViewById(R.id.switchMic)
        switchBoot = findViewById(R.id.switchBoot)
        btnPermNotification = findViewById(R.id.btnPermNotification)
        btnPermCamera = findViewById(R.id.btnPermCamera)
        btnPermMic = findViewById(R.id.btnPermMic)
        btnPermBattery = findViewById(R.id.btnPermBattery)
        btnSelectFolder = findViewById(R.id.btnSelectFolder)

        // Set device ID
        val deviceId = identityManager.getDeviceId()
        tvDeviceId.text = "This Device ID: $deviceId"

        // Set initial field values
        etRelayUrl.setText(secureStorage.getRelayUrl())
        switchCamera.isChecked = secureStorage.isCameraAllowed()
        switchMic.isChecked = secureStorage.isMicAllowed()
        switchBoot.isChecked = secureStorage.isAutoStartOnBoot()
    }

    private fun setupListeners() {
        // Camera toggle
        switchCamera.setOnCheckedChangeListener { _, isChecked ->
            secureStorage.setCameraAllowed(isChecked)
            if (isChecked && ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), REQ_CODE_CAMERA)
            }
        }

        // Microphone toggle
        switchMic.setOnCheckedChangeListener { _, isChecked ->
            secureStorage.setMicAllowed(isChecked)
            if (isChecked && ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) != PackageManager.PERMISSION_GRANTED) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), REQ_CODE_MIC)
            }
        }

        // Boot auto-start toggle
        switchBoot.setOnCheckedChangeListener { _, isChecked ->
            secureStorage.setAutoStartOnBoot(isChecked)
        }

        // Permission buttons
        btnPermNotification.setOnClickListener {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQ_CODE_NOTIFICATIONS)
            } else {
                Toast.makeText(this, "Notifications enabled by default on this Android version", Toast.LENGTH_SHORT).show()
            }
        }

        btnPermCamera.setOnClickListener {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), REQ_CODE_CAMERA)
        }

        btnPermMic.setOnClickListener {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.RECORD_AUDIO), REQ_CODE_MIC)
        }

        btnPermBattery.setOnClickListener {
            requestIgnoreBatteryOptimizations()
        }

        btnSelectFolder.setOnClickListener {
            openFolderLauncher.launch(null)
        }

        // Connect and pair button
        btnConnectPair.setOnClickListener {
            handleConnectAndPair()
        }

        // Unpair button
        btnUnpair.setOnClickListener {
            handleUnpair()
        }
    }

    private fun updateUIState() {
        val isPaired = secureStorage.isPaired()
        val pairedId = secureStorage.getPairedDeviceId()

        if (isPaired) {
            tvStatus.text = "🟢 Paired & Active (Peer: ${pairedId ?: "Mac"})"
            tvStatus.setTextColor(Color.parseColor("#2E7D32"))
            tvStatus.setBackgroundColor(Color.parseColor("#E8F5E9"))
            btnUnpair.visibility = View.VISIBLE
        } else {
            tvStatus.text = "⚫ Status: Not Paired"
            tvStatus.setTextColor(Color.parseColor("#C62828"))
            tvStatus.setBackgroundColor(Color.parseColor("#FFEBEE"))
            btnUnpair.visibility = View.GONE
        }

        // Check permission statuses and update button text
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val hasNotif = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
            btnPermNotification.text = if (hasNotif) "✓ Notification Permission (Granted)" else "Grant Notification Permission"
            btnPermNotification.isEnabled = !hasNotif
        } else {
            btnPermNotification.text = "✓ Notifications Active"
            btnPermNotification.isEnabled = false
        }

        val hasCamera = ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
        btnPermCamera.text = if (hasCamera) "✓ Camera Permission (Granted)" else "Grant Camera Permission"
        btnPermCamera.isEnabled = !hasCamera

        val hasMic = ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED
        btnPermMic.text = if (hasMic) "✓ Microphone Permission (Granted)" else "Grant Microphone Permission"
        btnPermMic.isEnabled = !hasMic

        val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
        if (powerManager != null && powerManager.isIgnoringBatteryOptimizations(packageName)) {
            btnPermBattery.text = "✓ Battery Optimization Ignored"
            btnPermBattery.isEnabled = false
        } else {
            btnPermBattery.text = "Disable Battery Optimization (Recommended)"
            btnPermBattery.isEnabled = true
        }

        val scopedTree = secureStorage.getScopedTreeUri()
        btnSelectFolder.text = if (!scopedTree.isNullOrEmpty()) {
            "✓ Shared Folder Selected (Tap to Change)"
        } else {
            "Select Shared Folder (Default: App Files)"
        }
    }

    private fun handleConnectAndPair() {
        val rawRelayUrl = etRelayUrl.text?.toString()?.trim().orEmpty()
        val pairingCode = etPairingCode.text?.toString()?.trim().orEmpty().uppercase()

        val httpBaseUrl = RelayUrlHelper.normalizeHttpBaseUrl(rawRelayUrl)
        if (httpBaseUrl.isEmpty()) {
            Toast.makeText(this, "Please enter a valid VPS Relay URL", Toast.LENGTH_SHORT).show()
            return
        }

        if (!secureStorage.isPaired() && pairingCode.isEmpty()) {
            Toast.makeText(this, "Please enter the pairing code from your Mac", Toast.LENGTH_SHORT).show()
            return
        }

        secureStorage.setRelayUrl(httpBaseUrl)

        btnConnectPair.isEnabled = false
        btnConnectPair.text = "Connecting..."

        executor.execute {
            try {
                // Step 1: Register device identity with VPS
                val regRes = authClient.registerDevice(httpBaseUrl, identityManager)
                if (regRes.isFailure) {
                    runOnUiThread {
                        btnConnectPair.isEnabled = true
                        btnConnectPair.text = "Connect & Pair"
                        Toast.makeText(this, "VPS Registration Failed: ${regRes.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
                    }
                    return@execute
                }

                // Step 2: Claim pairing if code provided
                if (pairingCode.isNotEmpty()) {
                    val claimRes = authClient.claimPairing(httpBaseUrl, pairingCode, identityManager)
                    if (claimRes.isFailure) {
                        runOnUiThread {
                            btnConnectPair.isEnabled = true
                            btnConnectPair.text = "Connect & Pair"
                            Toast.makeText(this, "Pairing Failed: ${claimRes.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
                        }
                        return@execute
                    }
                }

                // Step 3: Authenticate challenge-response
                val authRes = authClient.authenticate(httpBaseUrl, identityManager, keyManager)
                if (authRes.isFailure) {
                    runOnUiThread {
                        btnConnectPair.isEnabled = true
                        btnConnectPair.text = "Connect & Pair"
                        Toast.makeText(this, "Authentication Failed: ${authRes.exceptionOrNull()?.message}", Toast.LENGTH_LONG).show()
                    }
                    return@execute
                }

                // Step 4: Start background connection service
                ConnectionForegroundService.start(this@MainActivity)

                runOnUiThread {
                    btnConnectPair.isEnabled = true
                    btnConnectPair.text = "Connect & Pair"
                    etPairingCode.setText("")
                    updateUIState()
                    Toast.makeText(this, "Connected and paired successfully!", Toast.LENGTH_SHORT).show()
                }

            } catch (e: Exception) {
                runOnUiThread {
                    btnConnectPair.isEnabled = true
                    btnConnectPair.text = "Connect & Pair"
                    Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun handleUnpair() {
        ConnectionForegroundService.stop(this)
        secureStorage.clearPairing()
        secureStorage.saveSessionToken(null)
        secureStorage.clearResumptionToken()
        updateUIState()
        Toast.makeText(this, "Unpaired and disconnected", Toast.LENGTH_SHORT).show()
    }

    private fun requestIgnoreBatteryOptimizations() {
        val hint = oemBatteryGuidance(Build.MANUFACTURER)
        try {
            val detailsIntent = Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                data = Uri.parse("package:$packageName")
            }
            startActivity(detailsIntent)
            Toast.makeText(this, hint, Toast.LENGTH_LONG).show()
        } catch (_: Exception) {
            try {
                startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                Toast.makeText(this, hint, Toast.LENGTH_LONG).show()
            } catch (e: Exception) {
                Toast.makeText(this, "Unable to open battery settings: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun oemBatteryGuidance(manufacturer: String?): String {
        return when (manufacturer?.lowercase()?.trim()) {
            "realme", "oppo", "oneplus" ->
                "Open Battery usage -> Allow background activity & Auto-launch"
            "vivo", "iqoo" ->
                "Open Battery -> Allow high background power usage & Autostart"
            "xiaomi", "redmi", "poco" ->
                "Open Battery saver -> No restrictions, and enable Autostart"
            "samsung" ->
                "Open Battery -> select Unrestricted"
            else ->
                "Set App Battery usage to Unrestricted so PhoneLink stays connected"
        }
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        updateUIState()
        if (requestCode == REQ_CODE_CAMERA) {
            val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                switchCamera.isChecked = false
                secureStorage.setCameraAllowed(false)
                Toast.makeText(this, "Camera permission denied; remote camera toggle disabled", Toast.LENGTH_SHORT).show()
            }
        } else if (requestCode == REQ_CODE_MIC) {
            val granted = grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED
            if (!granted) {
                switchMic.isChecked = false
                secureStorage.setMicAllowed(false)
                Toast.makeText(this, "Microphone permission denied; remote mic toggle disabled", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
