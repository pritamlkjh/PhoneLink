package com.phonelink.mic

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import com.phonelink.storage.SecureStorage

/**
 * Dual-gate authorization controller for remote microphone activation.
 *
 * Enforces two independent gates before AudioRecord can ever activate remotely:
 *   Gate 1: OS runtime audio recording permission (android.permission.RECORD_AUDIO)
 *   Gate 2: Explicit in-app "Allow Remote Microphone Access" toggle (defaults to OFF)
 *
 * Neither gate alone is sufficient, and Gate 2 can never be enabled remotely.
 */
class MicAuthorizationGate(
    private val secureStorage: SecureStorage,
    private val permissionChecker: (permission: String) -> Boolean = { false }
) {
    companion object {
        const val MIC_PERMISSION = Manifest.permission.RECORD_AUDIO

        fun fromContext(context: Context, secureStorage: SecureStorage): MicAuthorizationGate {
            return MicAuthorizationGate(
                secureStorage = secureStorage,
                permissionChecker = { perm ->
                    context.checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED
                }
            )
        }
    }

    enum class AuthorizationStatus {
        AUTHORIZED,
        DENIED_OS_PERMISSION_MISSING,
        DENIED_IN_APP_TOGGLE_DISABLED,
        DENIED_BOTH_GATES_FAILED
    }

    data class AuthorizationDecision(
        val isAuthorized: Boolean,
        val status: AuthorizationStatus,
        val reason: String
    )

    /** Evaluates whether remote microphone capture is currently permitted by both gates. */
    fun evaluateRemoteActivation(osPermissionOverride: Boolean? = null): AuthorizationDecision {
        val osPermissionGranted = osPermissionOverride ?: permissionChecker(MIC_PERMISSION)
        val inAppToggleEnabled = secureStorage.isMicAllowed()

        return when {
            osPermissionGranted && inAppToggleEnabled -> AuthorizationDecision(
                isAuthorized = true,
                status = AuthorizationStatus.AUTHORIZED,
                reason = "Both OS microphone permission and in-app remote microphone toggle are granted."
            )
            !osPermissionGranted && !inAppToggleEnabled -> AuthorizationDecision(
                isAuthorized = false,
                status = AuthorizationStatus.DENIED_BOTH_GATES_FAILED,
                reason = "Denied: OS microphone permission is missing AND in-app remote microphone toggle is disabled."
            )
            !osPermissionGranted -> AuthorizationDecision(
                isAuthorized = false,
                status = AuthorizationStatus.DENIED_OS_PERMISSION_MISSING,
                reason = "Denied: OS microphone permission (RECORD_AUDIO) is not granted."
            )
            else -> AuthorizationDecision(
                isAuthorized = false,
                status = AuthorizationStatus.DENIED_IN_APP_TOGGLE_DISABLED,
                reason = "Denied: In-app remote microphone toggle is OFF."
            )
        }
    }

    fun isRemoteActivationPermitted(osPermissionOverride: Boolean? = null): Boolean =
        evaluateRemoteActivation(osPermissionOverride).isAuthorized

    fun isInAppToggleEnabled(): Boolean = secureStorage.isMicAllowed()

    fun setInAppToggle(enabled: Boolean) {
        secureStorage.setMicAllowed(enabled)
    }
}
