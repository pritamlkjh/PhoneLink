package com.phonelink.files

import android.content.Context
import java.io.File
import java.io.FileInputStream
import java.io.InputStream

/**
 * FILE-1: Android Storage Access Layer.
 *
 * Implements scoped storage boundaries, path validation, traversal protection,
 * and permission checking per ARCH-4 data-minimization constraints.
 */
class StorageAccessLayer(
    private val scopedRootDirectory: File,
    private val permissionChecker: () -> Boolean = { true }
) {
    companion object {
        // Blocklist of sensitive paths and filenames that must never be exposed
        private val SENSITIVE_PATTERNS = listOf(
            "shared_prefs",
            "databases",
            "key",
            "keystore",
            ".token",
            "phonelink_identity",
            "phonelink_secure_storage"
        )

        fun fromContext(context: Context): StorageAccessLayer {
            // Default scoped root is the app's external files directory or scoped downloads
            val scopedDir = context.getExternalFilesDir(null) ?: context.filesDir
            return StorageAccessLayer(scopedDir)
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

    /**
     * Checks if storage permission is currently granted.
     */
    fun hasPermission(): Boolean {
        return permissionChecker()
    }

    /**
     * Resolves and validates a relative path against the scoped root directory.
     * Prevents path traversal ("../") and access to blocked sensitive files.
     */
    fun resolveAndValidatePath(relativePath: String): Result<File> {
        if (!hasPermission()) {
            return Result.failure(StorageAccessException("Storage access permission denied"))
        }

        val cleanedRelative = relativePath.trim().trimStart('/', '\\')

        // Defense in depth: reject any path containing ".." components
        if (cleanedRelative.contains("..")) {
            return Result.failure(StorageAccessException("Path traversal detected: relative path cannot contain '..'"))
        }

        val targetFile = if (cleanedRelative.isEmpty()) {
            scopedRootDirectory
        } else {
            File(scopedRootDirectory, cleanedRelative)
        }

        // Canonical path validation
        val rootCanonical = scopedRootDirectory.canonicalPath
        val targetCanonical = targetFile.canonicalPath

        if (!targetCanonical.startsWith(rootCanonical)) {
            return Result.failure(StorageAccessException("Access denied: path '$cleanedRelative' is outside scoped root"))
        }

        // Blocklist check
        val lowerTarget = targetCanonical.lowercase()
        for (sensitive in SENSITIVE_PATTERNS) {
            if (lowerTarget.contains(sensitive)) {
                return Result.failure(StorageAccessException("Access denied: access to sensitive internal files is forbidden"))
            }
        }

        return Result.success(targetFile)
    }

    /**
     * Lists files within the scoped relative path.
     */
    fun listFiles(relativePath: String = ""): Result<List<ScopedFileInfo>> {
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
            val lower = fileCanonical.lowercase()
            // Skip sensitive files
            if (SENSITIVE_PATTERNS.any { lower.contains(it) }) {
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

    /**
     * Opens an InputStream to read a file within the scoped root.
     */
    fun openFile(relativePath: String): Result<InputStream> {
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
}
