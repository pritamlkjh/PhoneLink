package com.phonelink.transport

import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Normalizes user-entered relay server URLs into canonical HTTP(S) base URLs
 * and WebSocket endpoint URLs (`/ws/v1/connect`).
 */
object RelayUrlHelper {

    fun normalizeHttpBaseUrl(rawUrl: String): String {
        var url = rawUrl.trim()
        if (url.isEmpty()) return ""

        val lower = url.lowercase()
        url = when {
            lower.startsWith("wss://") -> "https://" + url.substring(6)
            lower.startsWith("ws://") -> "http://" + url.substring(5)
            lower.startsWith("https://") -> "https://" + url.substring(8)
            lower.startsWith("http://") -> "http://" + url.substring(7)
            else -> {
                val hostPart = url.substringBefore('/').substringBefore(':').lowercase()
                val isLocal = hostPart == "localhost" ||
                    hostPart.startsWith("127.") ||
                    hostPart.startsWith("10.") ||
                    hostPart.startsWith("192.168.") ||
                    isRfc172PrivateIp(hostPart)
                (if (isLocal) "http://" else "https://") + url
            }
        }

        // Strip any query parameters or /ws/... path suffix
        val queryIdx = url.indexOf('?')
        if (queryIdx != -1) {
            url = url.substring(0, queryIdx)
        }
        val wsPathIdx = url.indexOf("/ws/", ignoreCase = true)
        if (wsPathIdx != -1) {
            url = url.substring(0, wsPathIdx)
        }
        return url.trimEnd('/')
    }

    fun toWebSocketUrl(rawUrl: String, sessionToken: String): String {
        val httpBase = normalizeHttpBaseUrl(rawUrl)
        require(httpBase.isNotEmpty()) { "Relay URL must not be empty" }

        val wsBase = when {
            httpBase.startsWith("https://") -> "wss://" + httpBase.removePrefix("https://")
            httpBase.startsWith("http://") -> "ws://" + httpBase.removePrefix("http://")
            else -> "wss://$httpBase"
        }

        val encodedToken = URLEncoder.encode(sessionToken, StandardCharsets.UTF_8.name())
        return "$wsBase/ws/v1/connect?token=$encodedToken"
    }

    private fun isRfc172PrivateIp(host: String): Boolean {
        if (!host.startsWith("172.")) return false
        val parts = host.split('.')
        if (parts.size != 4) return false
        val second = parts[1].toIntOrNull() ?: return false
        return second in 16..31
    }
}
