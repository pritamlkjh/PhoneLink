package com.phonelink.files

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import com.phonelink.storage.SecureStorage
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.security.MessageDigest

/**
 * FILE-1: Android Storage Access Layer.
 *
 * Implements scoped storage boundaries, path validation, traversal protection,
 * and optional SAF (Storage Access Framework) shared folder support per ARCH-4.
 */
class StorageAccessLayer(
    private val scopedRootDirectory: File,
    private val safContext: Context? = null,
    private val safTreeUri: Uri? = null,
    private val stagingCacheDir: File? = null,
    private val permissionChecker: () -> Boolean = { true }
) {
    companion object {
        private val SENSITIVE_SEGMENT_EXACT = setOf(
            "databases",
            "keystore",
            ".android_secure",
            "keys.db"
        )
        private val SENSITIVE_SEGMENT_PREFIXES = listOf(
            "shared_prefs",
            "phonelink_identity",
            "phonelink_secure_storage",
            ".token",
            "phonelink-release.keystore"
        )

        fun fromContext(context: Context): StorageAccessLayer {
            val secureStorage = SecureStorage.fromContext(context)
            val treeStr = secureStorage.getScopedTreeUri()
            val treeUri = if (!treeStr.isNullOrEmpty()) {
                try {
                    val uri = Uri.parse(treeStr)
                    val hasPersistedGrant = context.contentResolver.persistedUriPermissions.any {
                        it.uri == uri && it.isReadPermission
                    }
                    if (hasPersistedGrant) uri else null
                } catch (_: Exception) {
                    null
                }
            } else {
                null
            }
            val scopedDir = context.getExternalFilesDir(null) ?: context.filesDir
            val cacheStage = File(context.cacheDir, "phonelink_uploads").apply { mkdirs() }
            return StorageAccessLayer(
                scopedRootDirectory = scopedDir,
                permissionChecker = { true },
                safContext = context.applicationContext,
                safTreeUri = treeUri,
                stagingCacheDir = cacheStage
            )
        }

        private fun isWithinRoot(rootCanonical: String, targetCanonical: String): Boolean {
            return targetCanonical == rootCanonical || targetCanonical.startsWith("$rootCanonical${File.separator}")
        }

        private fun isSensitivePath(canonicalOrRelPath: String): Boolean {
            val segments = canonicalOrRelPath.split('/', '\\')
                .map { it.trim().lowercase() }
                .filter { it.isNotEmpty() }
            for (seg in segments) {
                if (seg in SENSITIVE_SEGMENT_EXACT) return true
                if (SENSITIVE_SEGMENT_PREFIXES.any { seg.startsWith(it) }) return true
            }
            return false
        }
    }

    data class ScopedFileInfo(
        val name: String,
        val relativePath: String,
        val isDirectory: Boolean,
        val sizeBytes: Long,
        val lastModifiedMillis: Long
    )

    class StorageAccessException(message: String) : SecurityException(message)

    fun isUsingSaf(): Boolean = safContext != null && safTreeUri != null

    fun hasPermission(): Boolean {
        return permissionChecker()
    }

    private fun validateRelativeInput(relativePath: String): Result<String> {
        if (!hasPermission()) {
            return Result.failure(StorageAccessException("Storage access permission denied"))
        }
        val cleaned = relativePath.trim().trimStart('/', '\\')
        if (cleaned.contains("..")) {
            return Result.failure(StorageAccessException("Path traversal detected: relative path cannot contain '..'"))
        }
        if (isSensitivePath(cleaned)) {
            return Result.failure(StorageAccessException("Access denied: access to sensitive internal files is forbidden"))
        }
        return Result.success(cleaned)
    }

    fun resolveAndValidatePath(relativePath: String): Result<File> {
        val cleanedResult = validateRelativeInput(relativePath)
        if (cleanedResult.isFailure) return Result.failure(cleanedResult.exceptionOrNull()!!)
        val cleanedRelative = cleanedResult.getOrThrow()

        val targetFile = if (cleanedRelative.isEmpty()) {
            scopedRootDirectory
        } else {
            File(scopedRootDirectory, cleanedRelative)
        }

        val rootCanonical = scopedRootDirectory.canonicalPath
        val targetCanonical = targetFile.canonicalPath

        if (!isWithinRoot(rootCanonical, targetCanonical)) {
            return Result.failure(StorageAccessException("Access denied: path '$cleanedRelative' is outside scoped root"))
        }
        if (isSensitivePath(targetCanonical)) {
            return Result.failure(StorageAccessException("Access denied: access to sensitive internal files is forbidden"))
        }

        return Result.success(targetFile)
    }

    fun statFile(relativePath: String): Result<ScopedFileInfo> {
        if (isUsingSaf()) {
            return safStatFile(relativePath)
        }
        val pathResult = resolveAndValidatePath(relativePath)
        if (pathResult.isFailure) return Result.failure(pathResult.exceptionOrNull()!!)
        val f = pathResult.getOrThrow()
        if (!f.exists()) {
            return Result.failure(StorageAccessException("File does not exist: $relativePath"))
        }
        val rootCanonical = scopedRootDirectory.canonicalPath
        val rel = f.canonicalPath.removePrefix(rootCanonical).trimStart(File.separatorChar)
        return Result.success(
            ScopedFileInfo(
                name = f.name,
                relativePath = rel,
                isDirectory = f.isDirectory,
                sizeBytes = if (f.isDirectory) 0L else f.length(),
                lastModifiedMillis = f.lastModified()
            )
        )
    }

    fun computeSha256(relativePath: String): Result<String> {
        return try {
            val streamRes = openFile(relativePath)
            if (streamRes.isFailure) return Result.failure(streamRes.exceptionOrNull()!!)
            val digest = MessageDigest.getInstance("SHA-256")
            streamRes.getOrThrow().use { input ->
                val buf = ByteArray(65536)
                while (true) {
                    val r = input.read(buf)
                    if (r == -1) break
                    digest.update(buf, 0, r)
                }
            }
            Result.success(digest.digest().joinToString("") { "%02x".format(it) })
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun streamFileSlice(
        relativePath: String,
        startOffset: Long,
        totalSize: Long,
        chunkSizeBytes: Int,
        onSlice: (offset: Long, chunkBytes: ByteArray, isFinal: Boolean) -> Boolean
    ): Result<Long> {
        if (startOffset < 0 || startOffset > totalSize) {
            return Result.failure(StorageAccessException("Invalid start offset: $startOffset"))
        }

        if (isUsingSaf()) {
            val ctx = safContext!!
            val tree = safTreeUri!!
            val resolved = safResolveDocument(relativePath)
            if (resolved.isFailure) return Result.failure(resolved.exceptionOrNull()!!)
            val (_, docId, _) = resolved.getOrThrow()
            val docUri = DocumentsContract.buildDocumentUriUsingTree(tree, docId)
            return try {
                var chunksSent = 0L
                ctx.contentResolver.openFileDescriptor(docUri, "r")?.use { pfd ->
                    FileInputStream(pfd.fileDescriptor).channel.use { channel ->
                        channel.position(startOffset)
                        var currentOffset = startOffset
                        val buf = ByteBuffer.allocate(chunkSizeBytes)
                        while (currentOffset < totalSize) {
                            buf.clear()
                            val n = channel.read(buf)
                            if (n <= 0) break
                            val bytes = ByteArray(n)
                            buf.flip()
                            buf.get(bytes)
                            val isFinal = (currentOffset + n >= totalSize)
                            if (!onSlice(currentOffset, bytes, isFinal)) break
                            chunksSent++
                            currentOffset += n
                        }
                    }
                } ?: return Result.failure(StorageAccessException("Unable to open SAF file descriptor for: $relativePath"))
                Result.success(chunksSent)
            } catch (e: Exception) {
                Result.failure(e)
            }
        }

        val pathResult = resolveAndValidatePath(relativePath)
        if (pathResult.isFailure) return Result.failure(pathResult.exceptionOrNull()!!)
        val file = pathResult.getOrThrow()
        if (!file.exists() || file.isDirectory) {
            return Result.failure(StorageAccessException("File not found: $relativePath"))
        }

        return try {
            var chunksSent = 0L
            RandomAccessFile(file, "r").use { raf ->
                if (startOffset > 0) {
                    raf.seek(startOffset)
                }
                val buffer = ByteArray(chunkSizeBytes)
                var currentOffset = startOffset
                while (currentOffset < totalSize) {
                    val bytesToRead = minOf(chunkSizeBytes.toLong(), totalSize - currentOffset).toInt()
                    var readTotal = 0
                    while (readTotal < bytesToRead) {
                        val r = raf.read(buffer, readTotal, bytesToRead - readTotal)
                        if (r == -1) break
                        readTotal += r
                    }
                    if (readTotal == 0) break
                    val chunkBytes = if (readTotal == buffer.size) buffer else buffer.copyOf(readTotal)
                    val isFinal = (currentOffset + readTotal >= totalSize)
                    if (!onSlice(currentOffset, chunkBytes, isFinal)) {
                        break
                    }
                    chunksSent++
                    currentOffset += readTotal
                }
            }
            Result.success(chunksSent)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun listFiles(relativePath: String = ""): Result<List<ScopedFileInfo>> {
        if (isUsingSaf()) {
            return safListFiles(relativePath)
        }

        val pathResult = resolveAndValidatePath(relativePath)
        if (pathResult.isFailure) {
            return Result.failure(pathResult.exceptionOrNull() ?: StorageAccessException("Unknown path resolution error"))
        }

        val targetFile = pathResult.getOrThrow()
        if (!targetFile.exists()) {
            return Result.failure(StorageAccessException("Directory does not exist: $relativePath"))
        }
        if (!targetFile.isDirectory) {
            return Result.failure(StorageAccessException("Target path is not a directory: $relativePath"))
        }

        val files = targetFile.listFiles() ?: emptyArray()
        val rootCanonical = scopedRootDirectory.canonicalPath

        val infoList = files.mapNotNull { file ->
            val fileCanonical = file.canonicalPath
            if (isSensitivePath(fileCanonical)) {
                null
            } else {
                val rel = fileCanonical.removePrefix(rootCanonical).trimStart(File.separatorChar)
                ScopedFileInfo(
                    name = file.name,
                    relativePath = rel,
                    isDirectory = file.isDirectory,
                    sizeBytes = if (file.isDirectory) 0L else file.length(),
                    lastModifiedMillis = file.lastModified()
                )
            }
        }

        return Result.success(infoList)
    }

    fun openFile(relativePath: String): Result<InputStream> {
        if (isUsingSaf()) {
            val resolved = safResolveDocument(relativePath)
            if (resolved.isFailure) return Result.failure(resolved.exceptionOrNull()!!)
            val (_, docId, info) = resolved.getOrThrow()
            if (info.isDirectory) {
                return Result.failure(StorageAccessException("Target path is a directory, not a readable file: $relativePath"))
            }
            val docUri = DocumentsContract.buildDocumentUriUsingTree(safTreeUri!!, docId)
            return try {
                val stream = safContext!!.contentResolver.openInputStream(docUri)
                    ?: return Result.failure(StorageAccessException("Failed to open input stream for: $relativePath"))
                Result.success(stream)
            } catch (e: Exception) {
                Result.failure(e)
            }
        }

        val pathResult = resolveAndValidatePath(relativePath)
        if (pathResult.isFailure) {
            return Result.failure(pathResult.exceptionOrNull() ?: StorageAccessException("Unknown path error"))
        }

        val targetFile = pathResult.getOrThrow()
        if (!targetFile.exists()) {
            return Result.failure(StorageAccessException("File not found: $relativePath"))
        }
        if (targetFile.isDirectory) {
            return Result.failure(StorageAccessException("Target path is a directory, not a readable file: $relativePath"))
        }

        return try {
            Result.success(FileInputStream(targetFile))
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun prepareOutputFile(relativePath: String): Result<File> {
        if (isUsingSaf()) {
            val cleanedResult = validateRelativeInput(relativePath)
            if (cleanedResult.isFailure) return Result.failure(cleanedResult.exceptionOrNull()!!)
            val cleaned = cleanedResult.getOrThrow()
            val stageRoot = stagingCacheDir ?: File(scopedRootDirectory, ".staging").apply { mkdirs() }
            val stagedFile = File(stageRoot, cleaned)
            if (!isWithinRoot(stageRoot.canonicalPath, stagedFile.canonicalPath)) {
                return Result.failure(StorageAccessException("Security violation: staging target outside cache root"))
            }
            stagedFile.parentFile?.mkdirs()
            return Result.success(stagedFile)
        }

        val pathResult = resolveAndValidatePath(relativePath)
        if (pathResult.isFailure) return pathResult

        val targetFile = pathResult.getOrThrow()
        if (targetFile.exists() && targetFile.isDirectory) {
            return Result.failure(StorageAccessException("Target path is an existing directory, cannot overwrite: $relativePath"))
        }

        val parentDir = targetFile.parentFile
        if (parentDir != null && !parentDir.exists()) {
            val created = parentDir.mkdirs()
            if (!created && !parentDir.exists()) {
                return Result.failure(StorageAccessException("Failed to create parent directory for: $relativePath"))
            }
        }

        return Result.success(targetFile)
    }

    fun writeChunk(targetFile: File, offset: Long, data: ByteArray): Result<Unit> {
        return try {
            val rootCanonical = scopedRootDirectory.canonicalPath
            val stageCanonical = stagingCacheDir?.canonicalPath
            val targetCanonical = targetFile.canonicalPath
            val allowed = isWithinRoot(rootCanonical, targetCanonical) ||
                (stageCanonical != null && isWithinRoot(stageCanonical, targetCanonical))
            if (!allowed) {
                return Result.failure(StorageAccessException("Security violation: attempt to write outside scoped root"))
            }

            RandomAccessFile(targetFile, "rw").use { raf ->
                raf.seek(offset)
                raf.write(data)
            }
            Result.success(Unit)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    fun commitPartFile(partFile: File, finalFile: File, safRelativePath: String? = null): Result<File> {
        return try {
            if (isUsingSaf() && safRelativePath != null) {
                val res = safCommitFile(partFile, safRelativePath)
                if (res.isFailure) return Result.failure(res.exceptionOrNull()!!)
                partFile.delete()
                return Result.success(finalFile)
            }

            val rootCanonical = scopedRootDirectory.canonicalPath
            if (!isWithinRoot(rootCanonical, finalFile.canonicalPath) || !isWithinRoot(rootCanonical, partFile.canonicalPath)) {
                return Result.failure(StorageAccessException("Security violation: commit target outside scoped root"))
            }
            if (finalFile.exists()) {
                finalFile.delete()
            }
            val success = partFile.renameTo(finalFile)
            if (!success) {
                partFile.copyTo(finalFile, overwrite = true)
                partFile.delete()
            }
            Result.success(finalFile)
        } catch (e: Exception) {
            Result.failure(e)
        }
    }

    // --- SAF Document Tree Support ---

    private fun safResolveDocument(relativePath: String): Result<Triple<Uri, String, ScopedFileInfo>> {
        val cleanedRes = validateRelativeInput(relativePath)
        if (cleanedRes.isFailure) return Result.failure(cleanedRes.exceptionOrNull()!!)
        val cleaned = cleanedRes.getOrThrow()

        val ctx = safContext ?: return Result.failure(StorageAccessException("SAF context unavailable"))
        val tree = safTreeUri ?: return Result.failure(StorageAccessException("SAF tree URI unavailable"))
        var currentDocId = DocumentsContract.getTreeDocumentId(tree)
        var currentInfo = ScopedFileInfo("", "", true, 0L, 0L)

        if (cleaned.isEmpty()) {
            return Result.success(Triple(tree, currentDocId, currentInfo))
        }

        val segments = cleaned.split('/').filter { it.isNotEmpty() }
        for ((idx, seg) in segments.withIndex()) {
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, currentDocId)
            var foundDocId: String? = null
            var foundInfo: ScopedFileInfo? = null
            ctx.contentResolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                    DocumentsContract.Document.COLUMN_MIME_TYPE,
                    DocumentsContract.Document.COLUMN_SIZE,
                    DocumentsContract.Document.COLUMN_LAST_MODIFIED
                ),
                null,
                null,
                null
            )?.use { cursor ->
                val idIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
                val mimeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
                val sizeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
                val modIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
                while (cursor.moveToNext()) {
                    val name = if (nameIdx >= 0) cursor.getString(nameIdx) else continue
                    if (name == seg) {
                        val docId = if (idIdx >= 0) cursor.getString(idIdx) else continue
                        val mime = if (mimeIdx >= 0) cursor.getString(mimeIdx) else ""
                        val isDir = mime == DocumentsContract.Document.MIME_TYPE_DIR
                        val size = if (!isDir && sizeIdx >= 0) cursor.getLong(sizeIdx) else 0L
                        val mod = if (modIdx >= 0) cursor.getLong(modIdx) else 0L
                        val rel = segments.take(idx + 1).joinToString("/")
                        foundDocId = docId
                        foundInfo = ScopedFileInfo(name, rel, isDir, size, mod)
                        break
                    }
                }
            }
            if (foundDocId == null || foundInfo == null) {
                return Result.failure(StorageAccessException("Directory or file does not exist: $relativePath"))
            }
            if (idx < segments.size - 1 && !foundInfo!!.isDirectory) {
                return Result.failure(StorageAccessException("Path component '$seg' is not a directory"))
            }
            currentDocId = foundDocId!!
            currentInfo = foundInfo!!
        }

        val targetUri = DocumentsContract.buildDocumentUriUsingTree(tree, currentDocId)
        return Result.success(Triple(targetUri, currentDocId, currentInfo))
    }

    private fun safStatFile(relativePath: String): Result<ScopedFileInfo> {
        val res = safResolveDocument(relativePath)
        if (res.isFailure) return Result.failure(res.exceptionOrNull()!!)
        return Result.success(res.getOrThrow().third)
    }

    private fun safListFiles(relativePath: String): Result<List<ScopedFileInfo>> {
        val ctx = safContext ?: return Result.failure(StorageAccessException("SAF context unavailable"))
        val tree = safTreeUri ?: return Result.failure(StorageAccessException("SAF tree URI unavailable"))
        val resolved = safResolveDocument(relativePath)
        if (resolved.isFailure) return Result.failure(resolved.exceptionOrNull()!!)
        val (_, docId, info) = resolved.getOrThrow()
        if (!info.isDirectory) {
            return Result.failure(StorageAccessException("Target path is not a directory: $relativePath"))
        }
        val prefix = info.relativePath
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, docId)
        val out = mutableListOf<ScopedFileInfo>()
        ctx.contentResolver.query(
            childrenUri,
            arrayOf(
                DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                DocumentsContract.Document.COLUMN_MIME_TYPE,
                DocumentsContract.Document.COLUMN_SIZE,
                DocumentsContract.Document.COLUMN_LAST_MODIFIED
            ),
            null,
            null,
            null
        )?.use { cursor ->
            val nameIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            val mimeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_MIME_TYPE)
            val sizeIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_SIZE)
            val modIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_LAST_MODIFIED)
            while (cursor.moveToNext()) {
                val name = if (nameIdx >= 0) cursor.getString(nameIdx) else continue
                if (isSensitivePath(name)) continue
                val mime = if (mimeIdx >= 0) cursor.getString(mimeIdx) else ""
                val isDir = mime == DocumentsContract.Document.MIME_TYPE_DIR
                val size = if (!isDir && sizeIdx >= 0) cursor.getLong(sizeIdx) else 0L
                val mod = if (modIdx >= 0) cursor.getLong(modIdx) else 0L
                val rel = if (prefix.isEmpty()) name else "$prefix/$name"
                out.add(ScopedFileInfo(name, rel, isDir, size, mod))
            }
        }
        return Result.success(out)
    }

    private fun safCommitFile(partFile: File, safRelativePath: String): Result<Unit> {
        val ctx = safContext ?: return Result.failure(StorageAccessException("SAF context unavailable"))
        val tree = safTreeUri ?: return Result.failure(StorageAccessException("SAF tree URI unavailable"))
        val cleaned = safRelativePath.trim().trimStart('/', '\\')
        val segments = cleaned.split('/').filter { it.isNotEmpty() }
        if (segments.isEmpty()) {
            return Result.failure(StorageAccessException("Invalid SAF destination path"))
        }

        val dirSegments = segments.dropLast(1)
        val fileName = segments.last()
        var currentDocId = DocumentsContract.getTreeDocumentId(tree)

        // Ensure subdirectories exist
        for (dir in dirSegments) {
            val childId = findSafChildDocId(ctx, tree, currentDocId, dir)
            currentDocId = if (childId != null) {
                childId
            } else {
                val parentUri = DocumentsContract.buildDocumentUriUsingTree(tree, currentDocId)
                val createdUri = DocumentsContract.createDocument(
                    ctx.contentResolver,
                    parentUri,
                    DocumentsContract.Document.MIME_TYPE_DIR,
                    dir
                ) ?: return Result.failure(StorageAccessException("Failed to create SAF folder: $dir"))
                DocumentsContract.getDocumentId(createdUri)
            }
        }

        // Delete existing file with same name if present
        findSafChildDocId(ctx, tree, currentDocId, fileName)?.let { existingId ->
            val existingUri = DocumentsContract.buildDocumentUriUsingTree(tree, existingId)
            try {
                DocumentsContract.deleteDocument(ctx.contentResolver, existingUri)
            } catch (_: Exception) {}
        }

        val parentUri = DocumentsContract.buildDocumentUriUsingTree(tree, currentDocId)
        val mime = FileOperationHandler.guessMimeType(fileName, false)
        val destUri = DocumentsContract.createDocument(ctx.contentResolver, parentUri, mime, fileName)
            ?: return Result.failure(StorageAccessException("Failed to create SAF document: $fileName"))

        ctx.contentResolver.openOutputStream(destUri)?.use { out ->
            partFile.inputStream().use { inp ->
                inp.copyTo(out)
            }
        } ?: return Result.failure(StorageAccessException("Failed to write SAF document stream: $fileName"))

        return Result.success(Unit)
    }

    private fun findSafChildDocId(ctx: Context, tree: Uri, parentDocId: String, childName: String): String? {
        val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(tree, parentDocId)
        ctx.contentResolver.query(
            childrenUri,
            arrayOf(DocumentsContract.Document.COLUMN_DOCUMENT_ID, DocumentsContract.Document.COLUMN_DISPLAY_NAME),
            null,
            null,
            null
        )?.use { cursor ->
            val idIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
            val nameIdx = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)
            while (cursor.moveToNext()) {
                val name = if (nameIdx >= 0) cursor.getString(nameIdx) else continue
                if (name == childName && idIdx >= 0) {
                    return cursor.getString(idIdx)
                }
            }
        }
        return null
    }
}
