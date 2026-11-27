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

    data class FileUploadInitResponseDto(
        val transferId: String,
        val status: String,
        val resumeOffset: Long,
        val expectedChunkSize: Int,
        val errorMessage: String = ""
    )

    data class FileChunkAckDto(
        val transferId: String,
        val chunkIndex: Long,
        val status: String,
        val errorMessage: String = ""
    )

    data class ActiveUploadState(
        val transferId: String,
        val finalFile: File,
        val partFile: File,
        val relativePath: String,
        val totalSizeBytes: Long,
        val expectedSha256: String,
        val chunkSizeBytes: Int,
        var bytesWritten: Long
    )

    private val activeUploads = java.util.concurrent.ConcurrentHashMap<String, ActiveUploadState>()
    private val transferExecutor = java.util.concurrent.Executors.newFixedThreadPool(2) { r ->
        Thread(r, "PhoneLink-FileTransfer").apply { isDaemon = true }
    }

    fun shutdown() {
        activeUploads.clear()
        transferExecutor.shutdownNow()
    }

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
        val statResult = storageAccessLayer.statFile(filePath)
        if (statResult.isFailure) {
            val ex = statResult.exceptionOrNull()
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

        val info = statResult.getOrThrow()
        if (info.isDirectory) {
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

        val totalSize = info.sizeBytes
        if (startOffset < 0 || startOffset > totalSize) {
            return FileDownloadInitResponseDto(
                transferId = transferId,
                status = STATUS_STORAGE_ACCESS_DENIED,
                filePath = filePath,
                totalSizeBytes = totalSize,
                chunkSizeBytes = chunkSizeBytes,
                sha256Checksum = "",
                errorMessage = "Invalid resume offset: start_offset ($startOffset) out of range (0..$totalSize)"
            )
        }
        val shaRes = storageAccessLayer.computeSha256(filePath)
        if (shaRes.isFailure) {
            return FileDownloadInitResponseDto(
                transferId = transferId,
                status = STATUS_ERROR_UNKNOWN,
                filePath = filePath,
                totalSizeBytes = totalSize,
                chunkSizeBytes = chunkSizeBytes,
                sha256Checksum = "",
                errorMessage = shaRes.exceptionOrNull()?.message ?: "Checksum calculation failed"
            )
        }

        return FileDownloadInitResponseDto(
            transferId = transferId,
            status = STATUS_OK,
            filePath = filePath,
            totalSizeBytes = totalSize,
            chunkSizeBytes = chunkSizeBytes,
            sha256Checksum = shaRes.getOrThrow(),
            errorMessage = ""
        )
    }

    /**
     * Streams file chunks from startOffset to EOF using random-access seeking.
     * Emits a zero-byte final chunk if startOffset == totalSize so resumed completions never hang.
     */
    fun streamFileChunks(
        filePath: String,
        transferId: String,
        startOffset: Long = 0L,
        chunkSizeBytes: Int = DEFAULT_CHUNK_SIZE,
        onChunk: (ByteArray) -> Boolean
    ): Long {
        val statRes = storageAccessLayer.statFile(filePath)
        if (statRes.isFailure) return 0L
        val info = statRes.getOrThrow()
        if (info.isDirectory) return 0L

        val totalSize = info.sizeBytes
        if (startOffset < 0 || startOffset > totalSize) return 0L

        if (totalSize == 0L || startOffset == totalSize) {
            val emptyChunk = FileChunkDto(
                transferId = transferId,
                chunkIndex = 0L,
                offset = startOffset,
                dataBase64 = "",
                chunkSha256 = computeChunkSha256(ByteArray(0)),
                isFinalChunk = true
            )
            return if (onChunk(serializeFileChunk(emptyChunk))) 1L else 0L
        }

        var chunkIndex = 0L
        var chunksSent = 0L
        val sliceRes = storageAccessLayer.streamFileSlice(
            relativePath = filePath,
            startOffset = startOffset,
            totalSize = totalSize,
            chunkSizeBytes = chunkSizeBytes
        ) { offset, chunkBytes, isFinal ->
            val chunkDto = FileChunkDto(
                transferId = transferId,
                chunkIndex = chunkIndex,
                offset = offset,
                dataBase64 = Base64.getEncoder().encodeToString(chunkBytes),
                chunkSha256 = computeChunkSha256(chunkBytes),
                isFinalChunk = isFinal
            )
            val ok = onChunk(serializeFileChunk(chunkDto))
            if (ok) {
                chunksSent++
                chunkIndex++
            }
            ok
        }
        return if (sliceRes.isSuccess) chunksSent else chunksSent
    }

    /**
     * Initializes a file upload operation (FILE-4).
     * Strictly verifies write scope, path traversal protection, and checks for resumption offset.
     */
    fun handleFileUploadInit(
        transferId: String,
        destinationPath: String,
        fileName: String,
        totalSizeBytes: Long,
        sha256Checksum: String,
        expectedChunkSize: Int = DEFAULT_CHUNK_SIZE
    ): FileUploadInitResponseDto {
        if (totalSizeBytes < 0) {
            return FileUploadInitResponseDto(
                transferId = transferId,
                status = STATUS_STORAGE_ACCESS_DENIED,
                resumeOffset = 0L,
                expectedChunkSize = expectedChunkSize,
                errorMessage = "Invalid total file size: $totalSizeBytes"
            )
        }
        // Enforce strict filename validation (must be bare filename without traversal or path separators)
        if (fileName.contains("/") || fileName.contains("\\") || fileName.contains("..")) {
            return FileUploadInitResponseDto(
                transferId = transferId,
                status = STATUS_STORAGE_ACCESS_DENIED,
                resumeOffset = 0L,
                expectedChunkSize = expectedChunkSize,
                errorMessage = "Security violation: filename contains invalid path separators or '..'"
            )
        }

        val combinedRelPath = if (destinationPath.trim().isEmpty()) {
            fileName.trim()
        } else {
            "${destinationPath.trim().trimEnd('/', '\\')}/$fileName"
        }

        val prepResult = storageAccessLayer.prepareOutputFile(combinedRelPath)
        if (prepResult.isFailure) {
            val ex = prepResult.exceptionOrNull()
            val msg = ex?.message ?: "Unknown storage error"
            val status = if (msg.contains("Access denied", ignoreCase = true) ||
                msg.contains("traversal", ignoreCase = true) ||
                msg.contains("Security violation", ignoreCase = true) ||
                msg.contains("forbidden", ignoreCase = true)
            ) {
                STATUS_STORAGE_ACCESS_DENIED
            } else {
                STATUS_ERROR_UNKNOWN
            }
            return FileUploadInitResponseDto(
                transferId = transferId,
                status = status,
                resumeOffset = 0L,
                expectedChunkSize = expectedChunkSize,
                errorMessage = msg
            )
        }

        val finalFile = prepResult.getOrThrow()
        val partFile = File(finalFile.parentFile, "${finalFile.name}.part")

        // Check if partial file exists for resumption
        var resumeOffset = 0L
        if (partFile.exists()) {
            val existingLen = partFile.length()
            if (existingLen in 1 until totalSizeBytes) {
                resumeOffset = existingLen
            } else if (existingLen >= totalSizeBytes && totalSizeBytes > 0) {
                partFile.delete()
                resumeOffset = 0L
            }
        } else {
            partFile.createNewFile()
        }

        val uploadState = ActiveUploadState(
            transferId = transferId,
            finalFile = finalFile,
            partFile = partFile,
            relativePath = combinedRelPath,
            totalSizeBytes = totalSizeBytes,
            expectedSha256 = sha256Checksum,
            chunkSizeBytes = expectedChunkSize,
            bytesWritten = resumeOffset
        )
        activeUploads[transferId] = uploadState

        // Handle 0-byte file immediately
        if (totalSizeBytes == 0L) {
            val emptySha = computeChunkSha256(ByteArray(0))
            if (sha256Checksum.isNotEmpty() && !sha256Checksum.equals(emptySha, ignoreCase = true)) {
                partFile.delete()
                activeUploads.remove(transferId)
                return FileUploadInitResponseDto(
                    transferId = transferId,
                    status = STATUS_INTEGRITY_MISMATCH,
                    resumeOffset = 0L,
                    expectedChunkSize = expectedChunkSize,
                    errorMessage = "Checksum mismatch for 0-byte file"
                )
            }
            storageAccessLayer.commitPartFile(partFile, finalFile, combinedRelPath)
            activeUploads.remove(transferId)
        }

        return FileUploadInitResponseDto(
            transferId = transferId,
            status = STATUS_OK,
            resumeOffset = resumeOffset,
            expectedChunkSize = expectedChunkSize,
            errorMessage = ""
        )
    }

    /**
     * Handles an incoming uploaded chunk (FILE-4).
     * Verifies chunk SHA-256, writes chunk at offset, and verifies whole-file SHA-256 on final chunk.
     */
    fun handleFileUploadChunk(
        transferId: String,
        chunkIndex: Long,
        offset: Long,
        dataBase64: String,
        chunkSha256: String,
        isFinalChunk: Boolean
    ): FileChunkAckDto {
        val state = activeUploads[transferId]
        if (state == null) {
            return FileChunkAckDto(
                transferId = transferId,
                chunkIndex = chunkIndex,
                status = STATUS_NOT_FOUND,
                errorMessage = "No active upload session found for transfer: $transferId"
            )
        }

        val chunkBytes = try {
            Base64.getDecoder().decode(dataBase64)
        } catch (_: Exception) {
            return FileChunkAckDto(
                transferId = transferId,
                chunkIndex = chunkIndex,
                status = STATUS_ERROR_UNKNOWN,
                errorMessage = "Invalid base64 chunk payload"
            )
        }

        // Verify per-chunk SHA-256
        val actualChunkSha = computeChunkSha256(chunkBytes)
        if (!actualChunkSha.equals(chunkSha256, ignoreCase = true)) {
            return FileChunkAckDto(
                transferId = transferId,
                chunkIndex = chunkIndex,
                status = STATUS_INTEGRITY_MISMATCH,
                errorMessage = "STATUS_INTEGRITY_MISMATCH: Chunk $chunkIndex SHA-256 mismatch"
            )
        }

        // Bounds check upload offset before seeking
        if (offset < 0L || offset + chunkBytes.size > state.totalSizeBytes) {
            return FileChunkAckDto(
                transferId = transferId,
                chunkIndex = chunkIndex,
                status = STATUS_STORAGE_ACCESS_DENIED,
                errorMessage = "Invalid chunk offset/size ($offset + ${chunkBytes.size} > ${state.totalSizeBytes})"
            )
        }

        // Write chunk data
        val writeResult = storageAccessLayer.writeChunk(state.partFile, offset, chunkBytes)
        if (writeResult.isFailure) {
            return FileChunkAckDto(
                transferId = transferId,
                chunkIndex = chunkIndex,
                status = STATUS_STORAGE_ACCESS_DENIED,
                errorMessage = writeResult.exceptionOrNull()?.message ?: "Write failure"
            )
        }

        state.bytesWritten = maxOf(state.bytesWritten, offset + chunkBytes.size)

        if (isFinalChunk) {
            // Verify whole-file SHA-256
            val finalSha = computeFileSha256(state.partFile)
            if (state.expectedSha256.isNotEmpty() && !finalSha.equals(state.expectedSha256, ignoreCase = true)) {
                state.partFile.delete()
                activeUploads.remove(transferId)
                return FileChunkAckDto(
                    transferId = transferId,
                    chunkIndex = chunkIndex,
                    status = STATUS_INTEGRITY_MISMATCH,
                    errorMessage = "STATUS_INTEGRITY_MISMATCH: Whole-file SHA-256 mismatch (expected ${state.expectedSha256}, got $finalSha)"
                )
            }

            // Commit part file to final file
            val commitResult = storageAccessLayer.commitPartFile(state.partFile, state.finalFile, state.relativePath)
            activeUploads.remove(transferId)

            if (commitResult.isFailure) {
                return FileChunkAckDto(
                    transferId = transferId,
                    chunkIndex = chunkIndex,
                    status = STATUS_ERROR_UNKNOWN,
                    errorMessage = "Failed to commit uploaded file: ${commitResult.exceptionOrNull()?.message}"
                )
            }
        }

        return FileChunkAckDto(
            transferId = transferId,
            chunkIndex = chunkIndex,
            status = STATUS_OK,
            errorMessage = ""
        )
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

            if (sendAppMessage != null) {
                transferExecutor.execute {
                    val initDto = handleFileDownloadInit(filePath, startOffset, transferId)
                    val initBytes = serializeFileDownloadInitResponse(initDto)
                    val sentInit = sendAppMessage(initBytes)
                    if (sentInit && initDto.status == STATUS_OK) {
                        streamFileChunks(
                            filePath = filePath,
                            transferId = transferId,
                            startOffset = startOffset,
                            chunkSizeBytes = initDto.chunkSizeBytes,
                            onChunk = sendAppMessage
                        )
                    }
                }
                return null
            }

            val initDto = handleFileDownloadInit(filePath, startOffset, transferId)
            return serializeFileDownloadInitResponse(initDto)
        }

        if (json.has("file_upload_req")) {
            val req = json.getJSONObject("file_upload_req")
            val transferId = req.optString("transfer_id", UUID.randomUUID().toString())
            val destPath = req.optString("destination_path", "")
            val fileName = req.optString("file_name", "")
            val totalSize = req.optLong("total_size_bytes", 0L)
            val sha256 = req.optString("sha256_checksum", "")

            val initDto = handleFileUploadInit(transferId, destPath, fileName, totalSize, sha256)
            return serializeFileUploadInitResponse(initDto)
        }

        if (json.has("file_chunk")) {
            val chunk = json.getJSONObject("file_chunk")
            val transferId = chunk.optString("transfer_id", "")
            val chunkIndex = chunk.optLong("chunk_index", 0L)
            val offset = chunk.optLong("offset", 0L)
            val dataBase64 = chunk.optString("data", "")
            val chunkSha = chunk.optString("chunk_sha256", "")
            val isFinal = chunk.optBoolean("is_final_chunk", false)

            val ackDto = handleFileUploadChunk(transferId, chunkIndex, offset, dataBase64, chunkSha, isFinal)
            return serializeFileChunkAck(ackDto)
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

    /**
     * Serializes FileUploadInitResponseDto into standard ApplicationMessage JSON.
     */
    fun serializeFileUploadInitResponse(dto: FileUploadInitResponseDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val respObj = JSONObject().apply {
                put("transfer_id", dto.transferId)
                put("status", dto.status)
                put("resume_offset", dto.resumeOffset)
                put("expected_chunk_size", dto.expectedChunkSize)
                put("error_message", dto.errorMessage)
            }
            put("file_upload_init_resp", respObj)
        }

        return root.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Serializes FileChunkAckDto into standard ApplicationMessage JSON.
     */
    fun serializeFileChunkAck(dto: FileChunkAckDto): ByteArray {
        val root = JSONObject().apply {
            put("schema_version", SCHEMA_VERSION)
            put("message_id", UUID.randomUUID().toString())
            put("timestamp", System.currentTimeMillis())

            val ackObj = JSONObject().apply {
                put("transfer_id", dto.transferId)
                put("chunk_index", dto.chunkIndex)
                put("status", dto.status)
                if (dto.errorMessage.isNotEmpty()) {
                    put("error_message", dto.errorMessage)
                }
            }
            put("file_chunk_ack", ackObj)
        }

        return root.toString().toByteArray(Charsets.UTF_8)
    }
}
