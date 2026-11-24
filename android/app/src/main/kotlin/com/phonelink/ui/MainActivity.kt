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
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {

    companion object {
        private const val REQ_CODE_NOTIFICATIONS = 101
        private const val REQ_CODE_CAMERA = 102
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
    private lateinit var switchBoot: SwitchMaterial
    private lateinit var btnPermNotification: MaterialButton
    private lateinit var btnPermCamera: MaterialButton
    private lateinit var btnPermBattery: MaterialButton

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        // Initialize core dependencies
        secureStorage = SecureStorage.fromContext(this)
        identityManager = DeviceIdentityManager.fromContext(this)
        keyManager = KeyManager.fromContext(this)
        authClient = AuthClient(secureStorage = secureStorage)

        bindViews()
        setupListeners()
        updateUIState()
    }

    override fun onResume() {
        super.onResume()
        updateUIState()
    }

    override fun onDestroy() {
        super.onDestroy()
        executor.shutdown()
    }

    private fun bindViews() {
        tvDeviceId = findViewById(R.id.tvDeviceId)
        tvStatus = findViewById(R.id.tvStatus)
        etRelayUrl = findViewById(R.id.etRelayUrl)
        etPairingCode = findViewById(R.id.etPairingCode)
        btnConnectPair = findViewById(R.id.btnConnectPair)
        btnUnpair = findViewById(R.id.btnUnpair)
        switchCamera = findViewById(R.id.switchCamera)
        switchBoot = findViewById(R.id.switchBoot)
        btnPermNotification = findViewById(R.id.btnPermNotification)
        btnPermCamera = findViewById(R.id.btnPermCamera)
        btnPermBattery = findViewById(R.id.btnPermBattery)

        // Set device ID
        val deviceId = identityManager.getDeviceId()
        tvDeviceId.text = "This Device ID: $deviceId"

        // Set initial field values
        etRelayUrl.setText(secureStorage.getRelayUrl())
        switchCamera.isChecked = secureStorage.isCameraAllowed()
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

        btnPermBattery.setOnClickListener {
            requestIgnoreBatteryOptimizations()
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

        val powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
        if (powerManager != null && powerManager.isIgnoringBatteryOptimizations(packageName)) {
            btnPermBattery.text = "✓ Battery Optimization Ignored"
            btnPermBattery.isEnabled = false
        } else {
            btnPermBattery.text = "Disable Battery Optimization (Recommended)"
            btnPermBattery.isEnabled = true
        }
    }

    private fun handleConnectAndPair() {
        val relayUrl = etRelayUrl.text?.toString()?.trim().orEmpty()
        val pairingCode = etPairingCode.text?.toString()?.trim().orEmpty().uppercase()

        if (relayUrl.isEmpty()) {
            Toast.makeText(this, "Please enter a valid VPS Relay URL", Toast.LENGTH_SHORT).show()
            return
        }

        secureStorage.setRelayUrl(relayUrl)
        val httpBaseUrl = toHttpBaseUrl(relayUrl)

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

    @SuppressLint("BatteryLife")
    private fun requestIgnoreBatteryOptimizations() {
        try {
            val intent = Intent().apply {
                action = Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
                data = Uri.parse("package:$packageName")
            }
            startActivity(intent)
        } catch (_: Exception) {
            try {
                val intent = Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
                startActivity(intent)
            } catch (e: Exception) {
                Toast.makeText(this, "Unable to open battery settings: ${e.message}", Toast.LENGTH_SHORT).show()
            }
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
        }
    }

    private fun toHttpBaseUrl(relayUrl: String): String {
        var url = relayUrl.trim()
        if (url.startsWith("wss://")) {
            url = "https://" + url.removePrefix("wss://")
        } else if (url.startsWith("ws://")) {
            url = "http://" + url.removePrefix("ws://")
        }
        val idx = url.indexOf("/ws/")
        if (idx != -1) {
            url = url.substring(0, idx)
        }
        return url.removeSuffix("/")
    }
}
