package com.phonelink.auth

import com.phonelink.crypto.KeyManager
import com.phonelink.identity.DeviceIdentityManager
import com.phonelink.storage.SecureStorage
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.SecureRandom
import java.util.Base64

/**
 * AND-6: Android Authentication Handshake.
 *
 * Implements the client-side cryptographic challenge-response authentication
 * against VPS-2, token persistence in SecureStorage, and pairing claim flows.
 */
class AuthClient(
    private val okHttpClient: OkHttpClient = OkHttpClient(),
    private val secureStorage: SecureStorage
) {
    companion object {
        private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()
    }

    private val secureRandom = SecureRandom()

    fun cancelAll() {
        okHttpClient.dispatcher.cancelAll()
    }

    class AuthenticationException(message: String) : Exception(message)

    /**
     * Registers the Android device's identity public key with the VPS registry.
     */
    fun registerDevice(vpsBaseUrl: String, identityManager: DeviceIdentityManager): Result<Unit> {
        val identity = identityManager.getOrCreateIdentity()
        val pubKeyB64 = Base64.getEncoder().encodeToString(identity.publicKeyEncoded)

        val json = JSONObject().apply {
            put("device_id", identity.deviceId)
            put("device_type", "android")
            put("public_key", pubKeyB64)
            put("key_algorithm", "ECDSA_P256")
        }

        val request = Request.Builder()
            .url("$vpsBaseUrl/api/v1/devices/register")
            .post(json.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()

        return try {
            val response = okHttpClient.newCall(request).execute()
            response.use { resp ->
                if (resp.isSuccessful || resp.code == 409) { // 409 = already registered
                    Result.success(Unit)
                } else {
                    val body = resp.body?.string() ?: ""
                    Result.failure(AuthenticationException("Registration failed (HTTP ${resp.code}): $body"))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Completes the challenge-response authentication handshake against VPS-2.
     * Persists the resulting session token into SecureStorage.
     */
    fun authenticate(
        vpsBaseUrl: String,
        identityManager: DeviceIdentityManager,
        keyManager: KeyManager
    ): Result<String> {
        val deviceId = identityManager.getDeviceId()

        // Step 1: Request Auth Challenge
        val challengeReqJson = JSONObject().apply {
            put("device_id", deviceId)
        }

        val chRequest = Request.Builder()
            .url("$vpsBaseUrl/api/v1/auth/challenge")
            .post(challengeReqJson.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()

        val (serverNonce, timestamp) = try {
            val chResponse = okHttpClient.newCall(chRequest).execute()
            chResponse.use { resp ->
                if (!resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    return Result.failure(AuthenticationException("Challenge request failed (HTTP ${resp.code}): $body"))
                }
                val respJson = JSONObject(resp.body?.string() ?: "{}")
                val serverNonceB64 = respJson.getString("server_nonce")
                val ts = respJson.getLong("timestamp")
                Pair(Base64.getDecoder().decode(serverNonceB64), ts)
            }
        } catch (e: Exception) {
            return Result.failure(e)
        }

        // Step 2: Sign Challenge (serverNonce || clientNonce || timestamp)
        val clientNonce = ByteArray(32)
        secureRandom.nextBytes(clientNonce)

        val signature = keyManager.signChallenge(serverNonce, clientNonce, timestamp)

        // Step 3: Verify with VPS
        val verifyReqJson = JSONObject().apply {
            put("device_id", deviceId)
            put("server_nonce", Base64.getEncoder().encodeToString(serverNonce))
            put("client_nonce", Base64.getEncoder().encodeToString(clientNonce))
            put("timestamp", timestamp)
            put("signature", Base64.getEncoder().encodeToString(signature))
        }

        val verRequest = Request.Builder()
            .url("$vpsBaseUrl/api/v1/auth/verify")
            .post(verifyReqJson.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()

        return try {
            val verResponse = okHttpClient.newCall(verRequest).execute()
            verResponse.use { resp ->
                if (!resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    Result.failure(AuthenticationException("Handshake verification failed (HTTP ${resp.code}): $body"))
                } else {
                    val respJson = JSONObject(resp.body?.string() ?: "{}")
                    val sessionToken = respJson.getString("session_token")
                    val resumptionToken = respJson.optString("resumption_token", "")
                    val ttlSeconds = respJson.optLong("resumption_ttl_seconds", 300L)

                    // Step 4: Persist session & resumption token in secure storage (AND-4, AND-8)
                    secureStorage.saveSessionToken(sessionToken)
                    if (resumptionToken.isNotEmpty()) {
                        secureStorage.saveResumptionToken(resumptionToken, System.currentTimeMillis() + ttlSeconds * 1000L)
                    }
                    Result.success(sessionToken)
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Attempts fast session resumption using a bounded-validity resumption token (AND-8 / VPS-6).
     * Rotates the token upon success.
     */
    fun resumeSession(
        vpsBaseUrl: String,
        deviceId: String,
        resumptionToken: String
    ): Result<String> {
        val reqJson = JSONObject().apply {
            put("device_id", deviceId)
            put("resumption_token", resumptionToken)
        }

        val request = Request.Builder()
            .url("$vpsBaseUrl/api/v1/auth/resume")
            .post(reqJson.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()

        return try {
            val response = okHttpClient.newCall(request).execute()
            response.use { resp ->
                if (!resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    secureStorage.clearResumptionToken()
                    Result.failure(AuthenticationException("Resume failed (HTTP ${resp.code}): $body"))
                } else {
                    val respJson = JSONObject(resp.body?.string() ?: "{}")
                    val sessionToken = respJson.getString("session_token")
                    val newResumptionToken = respJson.optString("resumption_token", "")
                    val ttlSeconds = respJson.optLong("resumption_ttl_seconds", 300L)

                    secureStorage.saveSessionToken(sessionToken)
                    if (newResumptionToken.isNotEmpty()) {
                        secureStorage.saveResumptionToken(newResumptionToken, System.currentTimeMillis() + ttlSeconds * 1000L)
                    }
                    Result.success(sessionToken)
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    /**
     * Claims an out-of-band pairing token to establish pairing with the Mac.
     */
    fun claimPairing(
        vpsBaseUrl: String,
        pairingToken: String,
        identityManager: DeviceIdentityManager
    ): Result<String> {
        val deviceId = identityManager.getDeviceId()

        val json = JSONObject().apply {
            put("pairing_token", pairingToken)
            put("claimant_device_id", deviceId)
        }

        val request = Request.Builder()
            .url("$vpsBaseUrl/api/v1/pairing/claim")
            .post(json.toString().toRequestBody(JSON_MEDIA_TYPE))
            .build()

        return try {
            val response = okHttpClient.newCall(request).execute()
            response.use { resp ->
                if (!resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    Result.failure(AuthenticationException("Pairing claim failed (HTTP ${resp.code}): $body"))
                } else {
                    val respJson = JSONObject(resp.body?.string() ?: "{}")
                    val pairedPeerId = respJson.optString("paired_peer_id", "")
                    val pairedPubKey = respJson.optString("paired_public_key", "")
                    if (pairedPeerId.isNotEmpty()) {
                        secureStorage.savePairedDevice(pairedPeerId, pairedPubKey)
                    }
                    Result.success(pairedPeerId)
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    data class DeviceStatus(
        val deviceId: String,
        val isOnline: Boolean,
        val isPaired: Boolean,
        val peerDeviceId: String?,
        val peerPublicKey: String? = null,
        val peerKeyAlgorithm: String? = null,
        val peerOnline: Boolean,
        val timestamp: Long
    )

    /**
     * Queries the VPS relay for real-time status of this device and its paired peer.
     */
    fun getDeviceStatus(vpsBaseUrl: String, sessionToken: String): Result<DeviceStatus> {
        val request = Request.Builder()
            .url("$vpsBaseUrl/api/v1/devices/status")
            .header("Authorization", "Bearer $sessionToken")
            .get()
            .build()

        return try {
            val response = okHttpClient.newCall(request).execute()
            response.use { resp ->
                if (!resp.isSuccessful) {
                    val body = resp.body?.string() ?: ""
                    return Result.failure(AuthenticationException("Status query failed (HTTP ${resp.code}): $body"))
                }
                val json = JSONObject(resp.body?.string() ?: "{}")
                val peerId = if (json.has("peer_device_id")) json.getString("peer_device_id") else null
                val peerPub = if (json.has("peer_public_key")) json.optString("peer_public_key", "") else null
                val peerAlg = if (json.has("peer_key_algorithm")) json.optString("peer_key_algorithm", "") else null
                if (!peerId.isNullOrEmpty() && !peerPub.isNullOrEmpty()) {
                    secureStorage.savePairedDevice(peerId, peerPub)
                }
                Result.success(
                    DeviceStatus(
                        deviceId = json.getString("device_id"),
                        isOnline = json.getBoolean("is_online"),
                        isPaired = json.getBoolean("is_paired"),
                        peerDeviceId = peerId,
                        peerPublicKey = peerPub,
                        peerKeyAlgorithm = peerAlg,
                        peerOnline = json.getBoolean("peer_online"),
                        timestamp = json.getLong("timestamp")
                    )
                )
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
