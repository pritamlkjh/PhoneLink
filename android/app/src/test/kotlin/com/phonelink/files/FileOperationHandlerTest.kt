package com.phonelink.files

import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class FileOperationHandlerTest {

    private lateinit var tempRoot: File
    private lateinit var storageAccessLayer: StorageAccessLayer
    private lateinit var fileHandler: FileOperationHandler

    @Before
    fun setUp() {
        tempRoot = Files.createTempDirectory("phonelink_file_handler_test").toFile()
        storageAccessLayer = StorageAccessLayer(tempRoot) { true }
        fileHandler = FileOperationHandler(storageAccessLayer)
    }

    @After
    fun tearDown() {
        tempRoot.deleteRecursively()
    }

    @Test
    fun testHandleFileListSuccess() {
        // Create files and directory in scoped root
        val subDir = File(tempRoot, "Documents").apply { mkdir() }
        val testFile = File(subDir, "report.pdf").apply { writeText("Hello PDF Content") }
        val textFile = File(tempRoot, "notes.txt").apply { writeText("Sample Notes") }

        val response = fileHandler.handleFileList("Documents", "req-123")

        assertEquals("req-123", response.requestId)
        assertEquals(FileOperationHandler.STATUS_OK, response.status)
        assertEquals("Documents", response.currentDirectory)
        assertEquals(1, response.items.size)

        val item = response.items[0]
        assertEquals("report.pdf", item.name)
        assertFalse(item.isDirectory)
        assertEquals("application/pdf", item.mimeType)
        assertEquals(testFile.length(), item.sizeBytes)
    }

    @Test
    fun testHandleFileListRoot() {
        File(tempRoot, "photo.jpg").apply { writeText("Fake Image Bytes") }
        File(tempRoot, "Music").apply { mkdir() }

        val response = fileHandler.handleFileList("")

        assertEquals(FileOperationHandler.STATUS_OK, response.status)
        assertEquals(2, response.items.size)

        val musicDir = response.items.find { it.name == "Music" }
        assertNotNull(musicDir)
        assertTrue(musicDir.isDirectory)
        assertEquals("inode/directory", musicDir.mimeType)

        val photo = response.items.find { it.name == "photo.jpg" }
        assertNotNull(photo)
        assertFalse(photo.isDirectory)
        assertEquals("image/jpeg", photo.mimeType)
    }

    @Test
    fun testHandleFileListNotFound() {
        val response = fileHandler.handleFileList("NonExistentDir")
        assertEquals(FileOperationHandler.STATUS_NOT_FOUND, response.status)
        assertTrue(response.errorMessage.isNotEmpty())
    }

    @Test
    fun testHandleFileListRejectsPathTraversal() {
        val response = fileHandler.handleFileList("../../../etc")
        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, response.status)
        assertTrue(response.errorMessage.contains("traversal", ignoreCase = true))
    }

    @Test
    fun testHandleFileListRejectsSensitivePath() {
        val sensitiveDir = File(tempRoot, "keystore").apply { mkdir() }
        File(sensitiveDir, "keys.db").apply { writeText("secret") }

        val response = fileHandler.handleFileList("keystore")
        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, response.status)
    }

    @Test
    fun testProcessApplicationMessageRoundTrip() {
        File(tempRoot, "sample.json").apply { writeText("{\"key\":\"value\"}") }

        val requestJson = JSONObject().apply {
            put("schema_version", 1)
            put("message_id", "msg-001")
            put("timestamp", 123456789L)
            put("file_list_req", JSONObject().apply {
                put("request_id", "req-test-999")
                put("target_directory", "")
            })
        }

        val responseBytes = fileHandler.processApplicationMessage(requestJson.toString().toByteArray(Charsets.UTF_8))
        assertNotNull(responseBytes)

        val responseObj = JSONObject(String(responseBytes, Charsets.UTF_8))
        assertEquals(1, responseObj.getInt("schema_version"))
        assertTrue(responseObj.has("file_list_resp"))

        val respBody = responseObj.getJSONObject("file_list_resp")
        assertEquals("req-test-999", respBody.getString("request_id"))
        assertEquals("STATUS_OK", respBody.getString("status"))

        val items = respBody.getJSONArray("items")
        assertEquals(1, items.length())
        val item = items.getJSONObject(0)
        assertEquals("sample.json", item.getString("name"))
        assertEquals("application/json", item.getString("mime_type"))
    }

    @Test
    fun testHandleFileDownloadInitSuccess() {
        val sampleFile = File(tempRoot, "download_test.bin").apply {
            writeBytes(ByteArray(150_000) { (it % 256).toByte() })
        }
        val expectedSha256 = FileOperationHandler.computeFileSha256(sampleFile)

        val initResp = fileHandler.handleFileDownloadInit(
            filePath = "download_test.bin",
            startOffset = 0L,
            transferId = "transfer-101",
            chunkSizeBytes = 64 * 1024
        )

        assertEquals("transfer-101", initResp.transferId)
        assertEquals(FileOperationHandler.STATUS_OK, initResp.status)
        assertEquals("download_test.bin", initResp.filePath)
        assertEquals(150_000L, initResp.totalSizeBytes)
        assertEquals(64 * 1024, initResp.chunkSizeBytes)
        assertEquals(expectedSha256, initResp.sha256Checksum)
        assertEquals("", initResp.errorMessage)
    }

    @Test
    fun testHandleFileDownloadInitNotFound() {
        val initResp = fileHandler.handleFileDownloadInit(
            filePath = "missing_file.dat",
            startOffset = 0L,
            transferId = "transfer-404"
        )

        assertEquals(FileOperationHandler.STATUS_NOT_FOUND, initResp.status)
        assertTrue(initResp.errorMessage.contains("exist", ignoreCase = true))
    }

    @Test
    fun testHandleFileDownloadInitDirectoryForbidden() {
        File(tempRoot, "SubFolder").apply { mkdir() }

        val initResp = fileHandler.handleFileDownloadInit(
            filePath = "SubFolder",
            startOffset = 0L,
            transferId = "transfer-dir"
        )

        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, initResp.status)
        assertTrue(initResp.errorMessage.contains("directory", ignoreCase = true))
    }

    @Test
    fun testHandleFileDownloadInitPathTraversalForbidden() {
        val initResp = fileHandler.handleFileDownloadInit(
            filePath = "../../etc/shadow",
            startOffset = 0L,
            transferId = "transfer-traversal"
        )

        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, initResp.status)
        assertTrue(initResp.errorMessage.contains("traversal", ignoreCase = true))
    }

    @Test
    fun testStreamFileChunksComplete() {
        val sampleData = ByteArray(150_000) { (it % 256).toByte() }
        File(tempRoot, "stream_test.bin").apply { writeBytes(sampleData) }

        val collectedChunks = mutableListOf<JSONObject>()
        val totalChunks = fileHandler.streamFileChunks(
            filePath = "stream_test.bin",
            transferId = "tx-stream",
            startOffset = 0L,
            chunkSizeBytes = 64 * 1024,
            onChunk = { chunkBytes ->
                val json = JSONObject(String(chunkBytes, Charsets.UTF_8))
                collectedChunks.add(json.getJSONObject("file_chunk"))
                true
            }
        )

        // 150,000 / 65,536 = 2 full chunks (64KB each) + 1 partial chunk (18,928 bytes) = 3 chunks
        assertEquals(3L, totalChunks)
        assertEquals(3, collectedChunks.size)

        // Verify chunk 0
        val c0 = collectedChunks[0]
        assertEquals(0L, c0.getLong("chunk_index"))
        assertEquals(0L, c0.getLong("offset"))
        assertFalse(c0.getBoolean("is_final_chunk"))
        val d0 = java.util.Base64.getDecoder().decode(c0.getString("data"))
        assertEquals(65536, d0.size)
        assertEquals(FileOperationHandler.computeChunkSha256(d0), c0.getString("chunk_sha256"))

        // Verify chunk 1
        val c1 = collectedChunks[1]
        assertEquals(1L, c1.getLong("chunk_index"))
        assertEquals(65536L, c1.getLong("offset"))
        assertFalse(c1.getBoolean("is_final_chunk"))
        val d1 = java.util.Base64.getDecoder().decode(c1.getString("data"))
        assertEquals(65536, d1.size)
        assertEquals(FileOperationHandler.computeChunkSha256(d1), c1.getString("chunk_sha256"))

        // Verify chunk 2 (final)
        val c2 = collectedChunks[2]
        assertEquals(2L, c2.getLong("chunk_index"))
        assertEquals(131072L, c2.getLong("offset"))
        assertTrue(c2.getBoolean("is_final_chunk"))
        val d2 = java.util.Base64.getDecoder().decode(c2.getString("data"))
        assertEquals(18928, d2.size)
        assertEquals(FileOperationHandler.computeChunkSha256(d2), c2.getString("chunk_sha256"))

        // Reassemble and verify whole file
        val assembled = d0 + d1 + d2
        assertEquals(sampleData.size, assembled.size)
        assertTrue(sampleData.contentEquals(assembled))
    }

    @Test
    fun testStreamFileChunksResumeOffset() {
        val sampleData = ByteArray(100_000) { (it % 256).toByte() }
        File(tempRoot, "resume_test.bin").apply { writeBytes(sampleData) }

        val startOffset = 65536L
        val collectedChunks = mutableListOf<JSONObject>()

        val totalChunks = fileHandler.streamFileChunks(
            filePath = "resume_test.bin",
            transferId = "tx-resume",
            startOffset = startOffset,
            chunkSizeBytes = 64 * 1024,
            onChunk = { chunkBytes ->
                val json = JSONObject(String(chunkBytes, Charsets.UTF_8))
                collectedChunks.add(json.getJSONObject("file_chunk"))
                true
            }
        )

        assertEquals(1L, totalChunks)
        val c0 = collectedChunks[0]
        assertEquals(startOffset, c0.getLong("offset"))
        assertTrue(c0.getBoolean("is_final_chunk"))

        val chunkData = java.util.Base64.getDecoder().decode(c0.getString("data"))
        assertEquals((100_000 - startOffset).toInt(), chunkData.size)
        val expectedSlice = sampleData.copyOfRange(startOffset.toInt(), 100_000)
        assertTrue(expectedSlice.contentEquals(chunkData))
    }

    @Test
    fun testHandleFileUploadInitSuccess() {
        val initResp = fileHandler.handleFileUploadInit(
            transferId = "up-tx-001",
            destinationPath = "Uploads",
            fileName = "uploaded.bin",
            totalSizeBytes = 1024L,
            sha256Checksum = "dummy-sha",
            expectedChunkSize = 65536
        )

        assertEquals("up-tx-001", initResp.transferId)
        assertEquals(FileOperationHandler.STATUS_OK, initResp.status)
        assertEquals(0L, initResp.resumeOffset)
        assertEquals(65536, initResp.expectedChunkSize)
        assertEquals("", initResp.errorMessage)
    }

    @Test
    fun testHandleFileUploadInitTraversalRejection() {
        val initResp1 = fileHandler.handleFileUploadInit(
            transferId = "up-tx-trav-1",
            destinationPath = "../../../etc",
            fileName = "passwd",
            totalSizeBytes = 100L,
            sha256Checksum = "dummy"
        )
        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, initResp1.status)
        assertTrue(initResp1.errorMessage.contains("traversal", ignoreCase = true))

        val initResp2 = fileHandler.handleFileUploadInit(
            transferId = "up-tx-trav-2",
            destinationPath = "Uploads",
            fileName = "../../evil.sh",
            totalSizeBytes = 100L,
            sha256Checksum = "dummy"
        )
        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, initResp2.status)
        assertTrue(initResp2.errorMessage.contains("Security violation", ignoreCase = true))
    }

    @Test
    fun testHandleFileUploadInitSensitiveRejection() {
        val initResp = fileHandler.handleFileUploadInit(
            transferId = "up-tx-sens",
            destinationPath = "keystore",
            fileName = "keys.db",
            totalSizeBytes = 100L,
            sha256Checksum = "dummy"
        )
        assertEquals(FileOperationHandler.STATUS_STORAGE_ACCESS_DENIED, initResp.status)
        assertTrue(initResp.errorMessage.contains("forbidden", ignoreCase = true) || initResp.errorMessage.contains("sensitive", ignoreCase = true))
    }

    @Test
    fun testHandleFileUploadChunkCompleteFlow() {
        val testData = ByteArray(100_000) { (it % 127).toByte() }
        val testSha = FileOperationHandler.computeChunkSha256(testData)

        // 1. Init
        val initResp = fileHandler.handleFileUploadInit(
            transferId = "up-full-01",
            destinationPath = "Received",
            fileName = "data.bin",
            totalSizeBytes = 100_000L,
            sha256Checksum = testSha,
            expectedChunkSize = 65536
        )
        assertEquals(FileOperationHandler.STATUS_OK, initResp.status)

        // 2. Chunk 0 (65536 bytes)
        val chunk0Data = testData.copyOfRange(0, 65536)
        val chunk0Sha = FileOperationHandler.computeChunkSha256(chunk0Data)
        val ack0 = fileHandler.handleFileUploadChunk(
            transferId = "up-full-01",
            chunkIndex = 0L,
            offset = 0L,
            dataBase64 = java.util.Base64.getEncoder().encodeToString(chunk0Data),
            chunkSha256 = chunk0Sha,
            isFinalChunk = false
        )
        assertEquals(FileOperationHandler.STATUS_OK, ack0.status)

        // 3. Chunk 1 (34464 bytes, final)
        val chunk1Data = testData.copyOfRange(65536, 100_000)
        val chunk1Sha = FileOperationHandler.computeChunkSha256(chunk1Data)
        val ack1 = fileHandler.handleFileUploadChunk(
            transferId = "up-full-01",
            chunkIndex = 1L,
            offset = 65536L,
            dataBase64 = java.util.Base64.getEncoder().encodeToString(chunk1Data),
            chunkSha256 = chunk1Sha,
            isFinalChunk = true
        )
        assertEquals(FileOperationHandler.STATUS_OK, ack1.status)

        // 4. Verify file committed to scoped storage
        val finalFile = File(tempRoot, "Received/data.bin")
        assertTrue(finalFile.exists(), "Final uploaded file must exist")
        assertEquals(100_000L, finalFile.length())
        assertTrue(testData.contentEquals(finalFile.readBytes()))
        assertEquals(testSha, FileOperationHandler.computeFileSha256(finalFile))

        // .part file should be cleaned up
        val partFile = File(tempRoot, "Received/data.bin.part")
        assertFalse(partFile.exists(), ".part file must be removed after successful commit")
    }

    @Test
    fun testHandleFileUploadChunkTamperedRejection() {
        val testData = "Original Valid Chunk Content".toByteArray()
        val testSha = FileOperationHandler.computeChunkSha256(testData)

        fileHandler.handleFileUploadInit(
            transferId = "up-tamper-01",
            destinationPath = "Received",
            fileName = "tamper.txt",
            totalSizeBytes = testData.size.toLong(),
            sha256Checksum = testSha
        )

        val tamperedData = "Tampered Corrupted Content".toByteArray()
        val ack = fileHandler.handleFileUploadChunk(
            transferId = "up-tamper-01",
            chunkIndex = 0L,
            offset = 0L,
            dataBase64 = java.util.Base64.getEncoder().encodeToString(tamperedData),
            chunkSha256 = testSha, // mismatch with tamperedData
            isFinalChunk = true
        )

        assertEquals(FileOperationHandler.STATUS_INTEGRITY_MISMATCH, ack.status)
        assertTrue(ack.errorMessage.contains("STATUS_INTEGRITY_MISMATCH", ignoreCase = true))
    }
}
