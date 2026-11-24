package com.phonelink.camera

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import com.phonelink.storage.SecureStorage

/**
 * CAM-1: Camera Permission & Explicit Activation Authorization Flow.
 *
 * Enforces dual independent gates before the camera can ever activate remotely:
 *   Gate 1: OS runtime camera permission (android.permission.CAMERA)
 *   Gate 2: In-app "allow remote camera activation" opt-in toggle (defaults to OFF)
 *
 * Security Invariant (ARCH-4 / CAM-1):
 * Neither gate alone is sufficient. Remote activation requests are NEVER auto-approved.
 */
class CameraAuthorizationGate(
    private val secureStorage: SecureStorage,
    private val permissionChecker: (permission: String) -> Boolean = { false }
) {
    companion object {
        const val CAMERA_PERMISSION = Manifest.permission.CAMERA

        fun fromContext(context: Context, secureStorage: SecureStorage): CameraAuthorizationGate {
            return CameraAuthorizationGate(
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

    /**
     * Evaluates whether remote camera activation is permitted.
     * Checks both the OS runtime permission and the separate in-app toggle.
     */
    fun evaluateRemoteActivation(osPermissionOverride: Boolean? = null): AuthorizationDecision {
        val osPermissionGranted = osPermissionOverride ?: permissionChecker(CAMERA_PERMISSION)
        val inAppToggleEnabled = secureStorage.isCameraAllowed()

        return when {
            osPermissionGranted && inAppToggleEnabled -> {
                AuthorizationDecision(
                    isAuthorized = true,
                    status = AuthorizationStatus.AUTHORIZED,
                    reason = "Both OS camera permission and in-app remote activation toggle are granted."
                )
            }
            !osPermissionGranted && !inAppToggleEnabled -> {
                AuthorizationDecision(
                    isAuthorized = false,
                    status = AuthorizationStatus.DENIED_BOTH_GATES_FAILED,
                    reason = "Denied: OS camera permission is missing AND in-app remote activation toggle is disabled."
                )
            }
            !osPermissionGranted -> {
                AuthorizationDecision(
                    isAuthorized = false,
                    status = AuthorizationStatus.DENIED_OS_PERMISSION_MISSING,
                    reason = "Denied: OS camera permission is not granted."
                )
            }
            else -> {
                AuthorizationDecision(
                    isAuthorized = false,
                    status = AuthorizationStatus.DENIED_IN_APP_TOGGLE_DISABLED,
                    reason = "Denied: In-app remote camera activation toggle is OFF."
                )
            }
        }
    }

    /**
     * Fast check: returns true if and only if both authorization gates are satisfied.
     */
    fun isRemoteActivationPermitted(osPermissionOverride: Boolean? = null): Boolean {
        return evaluateRemoteActivation(osPermissionOverride).isAuthorized
    }

    /**
     * Returns whether the in-app opt-in toggle is currently enabled.
     * Default on fresh install must always be false.
     */
    fun isInAppToggleEnabled(): Boolean {
        return secureStorage.isCameraAllowed()
    }

    /**
     * Sets the in-app remote camera activation toggle.
     * This requires explicit local user interaction in the app UI.
     */
    fun setInAppToggle(enabled: Boolean) {
        secureStorage.setCameraAllowed(enabled)
    }
}
