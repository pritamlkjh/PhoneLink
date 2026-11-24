package com.phonelink.files

import org.junit.After
import org.junit.Before
import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class StorageAccessLayerTest {

    private lateinit var tempRoot: File
    private lateinit var outsideDir: File

    @Before
    fun setUp() {
        val baseTemp = File(System.getProperty("java.io.tmpdir"), "phonelink_storage_test_${System.currentTimeMillis()}")
        baseTemp.mkdirs()

        tempRoot = File(baseTemp, "scoped_root")
        tempRoot.mkdirs()

        outsideDir = File(baseTemp, "outside_root")
        outsideDir.mkdirs()

        // Create sample files in scoped root
        File(tempRoot, "document.pdf").writeText("Sample PDF content")
        val subDir = File(tempRoot, "downloads")
        subDir.mkdirs()
        File(subDir, "photo.jpg").writeText("Sample image content")

        // Create sensitive / outside files
        File(outsideDir, "secret_database.db").writeText("Top secret outside data")
        File(tempRoot, "shared_prefs_backup.xml").writeText("Private shared prefs")
    }

    @After
    fun tearDown() {
        tempRoot.parentFile?.deleteRecursively()
    }

    @Test
    fun testListFilesWithinScopedRoot() {
        val storage = StorageAccessLayer(tempRoot) { true }
        val result = storage.listFiles("")

        assertTrue(result.isSuccess, "Listing scoped root should succeed")
        val files = result.getOrThrow()

        // Should include document.pdf and downloads dir, but exclude sensitive shared_prefs_backup.xml
        assertTrue(files.any { it.name == "document.pdf" && !it.isDirectory })
        assertTrue(files.any { it.name == "downloads" && it.isDirectory })
        assertFalse(files.any { it.name.contains("shared_prefs") }, "Sensitive files must be filtered out")
    }

    @Test
    fun testListFilesSubdirectory() {
        val storage = StorageAccessLayer(tempRoot) { true }
        val result = storage.listFiles("downloads")

        assertTrue(result.isSuccess)
        val files = result.getOrThrow()
        assertEquals(1, files.size)
        assertEquals("photo.jpg", files[0].name)
    }

    @Test
    fun testReadFileContent() {
        val storage = StorageAccessLayer(tempRoot) { true }
        val result = storage.openFile("document.pdf")

        assertTrue(result.isSuccess)
        val content = result.getOrThrow().bufferedReader().use { it.readText() }
        assertEquals("Sample PDF content", content)
    }

    @Test
    fun testPathTraversalRejected() {
        val storage = StorageAccessLayer(tempRoot) { true }

        // Attempt traversal via ".."
        val traversalResult = storage.listFiles("../outside_root")
        assertTrue(traversalResult.isFailure, "Path traversal with '..' must fail")
        val ex = traversalResult.exceptionOrNull()
        assertNotNull(ex)
        assertTrue(ex is StorageAccessLayer.StorageAccessException)

        // Attempt reading file via ".."
        val fileResult = storage.openFile("../outside_root/secret_database.db")
        assertTrue(fileResult.isFailure, "Reading file via path traversal must fail")
    }

    @Test
    fun testSensitiveFileAccessForbidden() {
        val storage = StorageAccessLayer(tempRoot) { true }

        val result = storage.openFile("shared_prefs_backup.xml")
        assertTrue(result.isFailure, "Access to sensitive file pattern must be forbidden")
        val ex = result.exceptionOrNull()
        assertNotNull(ex)
        assertTrue(ex.message!!.contains("forbidden") || ex.message!!.contains("sensitive"))
    }

    @Test
    fun testPermissionDeniedHandling() {
        // Permission checker returns false (denied)
        val storage = StorageAccessLayer(tempRoot) { false }

        val listResult = storage.listFiles("")
        assertTrue(listResult.isFailure, "Listing without permission must fail gracefully")
        assertTrue(listResult.exceptionOrNull() is StorageAccessLayer.StorageAccessException)

        val readResult = storage.openFile("document.pdf")
        assertTrue(readResult.isFailure, "Reading without permission must fail gracefully")
        assertTrue(readResult.exceptionOrNull() is StorageAccessLayer.StorageAccessException)
    }

    @Test
    fun testNonExistentPathHandling() {
        val storage = StorageAccessLayer(tempRoot) { true }

        val result = storage.openFile("non_existent_file.txt")
        assertTrue(result.isFailure)
        assertTrue(result.exceptionOrNull()!!.message!!.contains("File not found"))
    }
}
