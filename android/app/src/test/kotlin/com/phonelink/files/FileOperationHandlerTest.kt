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
}
