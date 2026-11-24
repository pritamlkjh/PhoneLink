package com.phonelink.files

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.security.MessageDigest
import java.util.Base64
import java.util.UUID

/**
 * FILE-2 / FILE-3: Android Remote File Operation Handler.
 *
 * Dispatches decrypted E2E application payloads to StorageAccessLayer (FILE-1)
 * and formats compliant responses per ARCH-3 / API_CONTRACT.md.
 * Handles directory listing (FILE-2) and chunked file downloading with
 * SHA-256 integrity verification and resumability (FILE-3).
 */
class FileOperationHandler(
    private val storageAccessLayer: StorageAccessLayer
) {
    companion object {
        const val SCHEMA_VERSION = 1
        const val DEFAULT_CHUNK_SIZE = 64 * 1024 // 64 KB chunk size

        const val STATUS_OK = "STATUS_OK"
        const val STATUS_NOT_FOUND = "STATUS_NOT_FOUND"
        const val STATUS_STORAGE_ACCESS_DENIED = "STATUS_STORAGE_ACCESS_DENIED"
        const val STATUS_ERROR_UNKNOWN = "STATUS_ERROR_UNKNOWN"
        const val STATUS_INTEGRITY_MISMATCH = "STATUS_INTEGRITY_MISMATCH"

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

        fun computeFileSha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            file.inputStream().use { fis ->
                val buffer = ByteArray(65536)
                var bytesRead: Int
                while (fis.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            return digest.digest().joinToString("") { "%02x".format(it) }
        }

        fun computeChunkSha256(chunkData: ByteArray): String {
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(chunkData)
            return digest.digest().joinToString("") { "%02x".format(it) }
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

    data class FileDownloadInitResponseDto(
        val transferId: String,
        val status: String,
        val filePath: String,
        val totalSizeBytes: Long,
        val chunkSizeBytes: Int,
        val sha256Checksum: String,
        val errorMessage: String = ""
    )

    data class FileChunkDto(
        val transferId: String,
        val chunkIndex: Long,
        val offset: Long,
        val dataBase64: String,
        val chunkSha256: String,
        val isFinalChunk: Boolean
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
     * Prepares and initializes file download against StorageAccessLayer.
     */
    fun handleFileDownloadInit(
        filePath: String,
        startOffset: Long = 0L,
        transferId: String = UUID.randomUUID().toString(),
        chunkSizeBytes: Int = DEFAULT_CHUNK_SIZE
    ): FileDownloadInitResponseDto {
        val pathResult = storageAccessLayer.resolveAndValidatePath(filePath)
        if (pathResult.isFailure) {
            val ex = pathResult.exceptionOrNull()
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
            return FileDownloadInitResponseDto(
                transferId = transferId,
                status = status,
                filePath = filePath,
                totalSizeBytes = 0L,
                chunkSizeBytes = chunkSizeBytes,
                sha256Checksum = "",
                errorMessage = msg
            )
        }

        val targetFile = pathResult.getOrThrow()
        if (!targetFile.exists()) {
            return FileDownloadInitResponseDto(
                transferId = transferId,
                status = STATUS_NOT_FOUND,
                filePath = filePath,
                totalSizeBytes = 0L,
                chunkSizeBytes = chunkSizeBytes,
                sha256Checksum = "",
                errorMessage = "File does not exist: $filePath"
            )
        }

        if (targetFile.isDirectory) {
            return FileDownloadInitResponseDto(
                transferId = transferId,
                status = STATUS_STORAGE_ACCESS_DENIED,
                filePath = filePath,
                totalSizeBytes = 0L,
                chunkSizeBytes = chunkSizeBytes,
                sha256Checksum = "",
                errorMessage = "Target path is a directory, not a downloadable file: $filePath"
            )
        }

        val totalSize = targetFile.length()
        if (startOffset > totalSize) {
            return FileDownloadInitResponseDto(
                transferId = transferId,
                status = STATUS_STORAGE_ACCESS_DENIED,
                filePath = filePath,
                totalSizeBytes = totalSize,
                chunkSizeBytes = chunkSizeBytes,
                sha256Checksum = "",
                errorMessage = "Invalid resume offset: start_offset ($startOffset) exceeds total size ($totalSize)"
            )
        }
        val checksum = computeFileSha256(targetFile)

        return FileDownloadInitResponseDto(
            transferId = transferId,
            status = STATUS_OK,
            filePath = filePath,
            totalSizeBytes = totalSize,
            chunkSizeBytes = chunkSizeBytes,
            sha256Checksum = checksum,
            errorMessage = ""
        )
    }

    /**
     * Streams file chunks from startOffset to EOF.
     * Invokes onChunk callback with serialized ApplicationMessage for each chunk.
     * Returns total number of chunks successfully streamed.
     */
    fun streamFileChunks(
        filePath: String,
        transferId: String,
        startOffset: Long = 0L,
        chunkSizeBytes: Int = DEFAULT_CHUNK_SIZE,
        onChunk: (ByteArray) -> Boolean
    ): Long {
        val pathResult = storageAccessLayer.resolveAndValidatePath(filePath)
        if (pathResult.isFailure) return 0L
        val file = pathResult.getOrThrow()
        if (!file.exists() || file.isDirectory) return 0L

        val totalSize = file.length()
        var chunkIndex = 0L
        var currentOffset = startOffset
        var chunksSent = 0L

        if (totalSize == 0L) {
            val emptyChunk = FileChunkDto(
                transferId = transferId,
                chunkIndex = 0L,
                offset = 0L,
                dataBase64 = "",
                chunkSha256 = computeChunkSha256(ByteArray(0)),
                isFinalChunk = true
            )
            onChunk(serializeFileChunk(emptyChunk))
            return 1L
        }

        file.inputStream().use { stream ->
            if (startOffset > 0) {
                var skipped = 0L
                while (skipped < startOffset) {
                    val s = stream.skip(startOffset - skipped)
                    if (s <= 0) break
                    skipped += s
                }
            }

            val buffer = ByteArray(chunkSizeBytes)
            while (currentOffset < totalSize) {
                val bytesToRead = minOf(chunkSizeBytes.toLong(), totalSize - currentOffset).toInt()
                var readTotal = 0
                while (readTotal < bytesToRead) {
                    val r = stream.read(buffer, readTotal, bytesToRead - readTotal)
                    if (r == -1) break
                    readTotal += r
                }
                if (readTotal == 0) break

                val chunkBytes = if (readTotal == buffer.size) buffer else buffer.copyOf(readTotal)
                val chunkSha = computeChunkSha256(chunkBytes)
                val isFinal = (currentOffset + readTotal >= totalSize)

                val chunkDto = FileChunkDto(
                    transferId = transferId,
                    chunkIndex = chunkIndex,
                    offset = currentOffset,
                    dataBase64 = Base64.getEncoder().encodeToString(chunkBytes),
                    chunkSha256 = chunkSha,
                    isFinalChunk = isFinal
                )

                val serialized = serializeFileChunk(chunkDto)
                val ok = onChunk(serialized)
                if (!ok) {
                    break
                }

                chunksSent++
                chunkIndex++
                currentOffset += readTotal
            }
        }
        return chunksSent
    }

    /**
     * Processes a decrypted ApplicationMessage JSON payload.
     * Returns serialized response bytes if message is a recognized file request.
     * If sendAppMessage is provided, streaming file operations (like download) can emit chunk frames.
     */
    fun processApplicationMessage(
        payloadBytes: ByteArray,
        sendAppMessage: ((ByteArray) -> Boolean)? = null
    ): ByteArray? {
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

        if (json.has("file_download_req")) {
            val req = json.getJSONObject("file_download_req")
            val transferId = req.optString("transfer_id", UUID.randomUUID().toString())
            val filePath = req.optString("file_path", "")
            val startOffset = req.optLong("start_offset", 0L)

            val initDto = handleFileDownloadInit(filePath, startOffset, transferId)
            val initResponseBytes = serializeFileDownloadInitResponse(initDto)

            if (initDto.status == STATUS_OK && sendAppMessage != null) {
                // Stream chunks asynchronously to not block message dispatching
                Thread({
                    streamFileChunks(
                        filePath = filePath,
                        transferId = transferId,
                        startOffset = startOffset,
                        chunkSizeBytes = initDto.chunkSizeBytes,
                        onChunk = sendAppMessage
                    )
                }, "PhoneLink-FileDownload-Stream").start()
            }

            return initResponseBytes
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

    /**
     * Serializes FileDownloadInitResponseDto into standard ApplicationMessage JSON.
     */
    fun serializeFileDownloadInitResponse(dto: FileDownloadInitResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("transfer_id", dto.transferId)
                put("status", dto.status)
                put("file_path", dto.filePath)
                put("total_size_bytes", dto.totalSizeBytes)
                put("chunk_size_bytes", dto.chunkSizeBytes)
                put("sha256_checksum", dto.sha256Checksum)
                put("error_message", dto.errorMessage)
            }
            put("file_download_init_resp", respObj)
        }

        return root.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Serializes FileChunkDto into standard ApplicationMessage JSON.
     */
    fun serializeFileChunk(dto: FileChunkDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val chunkObj = JSONObject().apply {
                put("transfer_id", dto.transferId)
                put("chunk_index", dto.chunkIndex)
                put("offset", dto.offset)
                put("data", dto.dataBase64)
                put("chunk_sha256", dto.chunkSha256)
                put("is_final_chunk", dto.isFinalChunk)
            }
            put("file_chunk", chunkObj)
        }

        return root.toString().toByteArray(Charsets.UTF_8)
    }
}
