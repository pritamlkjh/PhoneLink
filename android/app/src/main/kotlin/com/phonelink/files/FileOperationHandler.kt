package com.phonelink.files

import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * FILE-2: Android Remote File Operation Handler.
 *
 * Dispatches decrypted E2E application payloads to StorageAccessLayer (FILE-1)
 * and formats compliant responses per ARCH-3 / API_CONTRACT.md.
 */
class FileOperationHandler(
    private val storageAccessLayer: StorageAccessLayer
) {
    companion object {
        const val SCHEMA_VERSION = 1

        const val STATUS_OK = "STATUS_OK"
        const val STATUS_NOT_FOUND = "STATUS_NOT_FOUND"
        const val STATUS_STORAGE_ACCESS_DENIED = "STATUS_STORAGE_ACCESS_DENIED"
        const val STATUS_ERROR_UNKNOWN = "STATUS_ERROR_UNKNOWN"

        fun guessMimeType(fileName: String, isDirectory: Boolean): String {
            if (isDirectory) return "inode/directory"
            val ext = fileName.substringAfterLast('.', "").lowercase()
            return when (ext) {
                "txt" -> "text/plain"
                "pdf" -> "application/pdf"
                "json" -> "application/json"
                "jpg", "jpeg" -> "image/jpeg"
                "png" -> "image/png"
                "gif" -> "image/gif"
                "mp4" -> "video/mp4"
                "mp3" -> "audio/mpeg"
                "zip" -> "application/zip"
                "html" -> "text/html"
                else -> "application/octet-stream"
            }
        }
    }

    data class FileItemDto(
        val path: String,
        val name: String,
        val isDirectory: Boolean,
        val sizeBytes: Long,
        val modifiedTime: Long,
        val mimeType: String
    )

    data class FileListResponseDto(
        val requestId: String,
        val status: String,
        val currentDirectory: String,
        val items: List<FileItemDto>,
        val errorMessage: String = ""
    )

    /**
     * Executes directory listing against StorageAccessLayer.
     */
    fun handleFileList(targetDirectory: String, requestId: String = UUID.randomUUID().toString()): FileListResponseDto {
        val result = storageAccessLayer.listFiles(targetDirectory)

        return if (result.isSuccess) {
            val fileList = result.getOrThrow().map { info ->
                FileItemDto(
                    path = info.relativePath,
                    name = info.name,
                    isDirectory = info.isDirectory,
                    sizeBytes = info.sizeBytes,
                    modifiedTime = info.lastModifiedMillis,
                    mimeType = guessMimeType(info.name, info.isDirectory)
                )
            }
            FileListResponseDto(
                requestId = requestId,
                status = STATUS_OK,
                currentDirectory = targetDirectory,
                items = fileList
            )
        } else {
            val ex = result.exceptionOrNull()
            val msg = ex?.message ?: "Unknown storage error"
            val status = if (msg.contains("Access denied", ignoreCase = true) ||
                msg.contains("Path traversal", ignoreCase = true) ||
                msg.contains("permission denied", ignoreCase = true) ||
                msg.contains("forbidden", ignoreCase = true)
            ) {
                STATUS_STORAGE_ACCESS_DENIED
            } else if (msg.contains("does not exist", ignoreCase = true) ||
                msg.contains("not found", ignoreCase = true)
            ) {
                STATUS_NOT_FOUND
            } else {
                STATUS_ERROR_UNKNOWN
            }

            FileListResponseDto(
                requestId = requestId,
                status = status,
                currentDirectory = targetDirectory,
                items = emptyList(),
                errorMessage = msg
            )
        }
    }

    /**
     * Processes a decrypted ApplicationMessage JSON payload.
     * Returns serialized response bytes if message is a recognized file request.
     */
    fun processApplicationMessage(payloadBytes: ByteArray): ByteArray? {
        val payloadStr = String(payloadBytes, Charsets.UTF_8)
        val json = try {
            JSONObject(payloadStr)
        } catch (_: Exception) {
            return null
        }

        if (json.has("file_list_req")) {
            val req = json.getJSONObject("file_list_req")
            val requestId = req.optString("request_id", UUID.randomUUID().toString())
            val targetDir = req.optString("target_directory", "")

            val responseDto = handleFileList(targetDir, requestId)
            return serializeResponse(responseDto)
        }

        return null
    }

    /**
     * Serializes FileListResponseDto into standard ApplicationMessage JSON.
     */
    fun serializeResponse(dto: FileListResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("request_id", dto.requestId)
                put("status", dto.status)
                put("current_directory", dto.currentDirectory)
                put("error_message", dto.errorMessage)

                val itemsArray = JSONArray()
                for (item in dto.items) {
                    val itemObj = JSONObject().apply {
                        put("path", item.path)
                        put("name", item.name)
                        put("is_directory", item.isDirectory)
                        put("size_bytes", item.sizeBytes)
                        put("modified_time", item.modifiedTime)
                        put("mime_type", item.mimeType)
                    }
                    itemsArray.put(itemObj)
                }
                put("items", itemsArray)
            }
            put("file_list_resp", respObj)
        }

        return root.toString().toByteArray(Charsets.UTF_8)
    }
}
