package pl.siedlar.securityguardian.quarantine

import android.content.ContentResolver
import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

enum class QuarantineOutcome {
    CONTAINED,
    VAULT_COPY_ONLY,
    FAILED,
}

enum class RestoreOutcome {
    RESTORED,
    HASH_MISMATCH,
    FAILED,
}

data class QuarantineRecord(
    val id: String,
    val originalUri: String,
    val originalDisplayName: String,
    val sha256: String,
    val vaultFileName: String,
    val createdAtEpochMs: Long,
    val originalRemovalRequested: Boolean,
    val originalRemoved: Boolean,
    val outcome: QuarantineOutcome,
    val detail: String,
)

data class RestoreResult(
    val outcome: RestoreOutcome,
    val sha256: String?,
    val vaultCopyRemoved: Boolean,
    val detail: String,
)

class AndroidFileQuarantine(
    context: Context,
    private val maxBytes: Long = 512L * 1024L * 1024L,
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    private val appContext = context.applicationContext
    private val resolver: ContentResolver = appContext.contentResolver
    private val vaultDir = File(appContext.filesDir, "quarantine").apply {
        check(exists() || mkdirs()) { "Cannot create quarantine directory" }
    }

    init {
        require(maxBytes > 0) { "maxBytes must be positive" }
    }

    fun quarantine(
        uri: Uri,
        expectedSha256: String,
        displayName: String,
        removeOriginalAfterVerifiedCopy: Boolean,
    ): QuarantineRecord {
        val normalizedExpected = normalizeSha256(expectedSha256)
        val createdAt = now()
        val extension = safeExtension(displayName)
        val targetName = normalizedExpected + extension
        val target = File(vaultDir, targetName)
        val temp = File.createTempFile("quarantine-", ".tmp", vaultDir)

        return try {
            val copiedHash = resolver.openInputStream(uri)?.use { input ->
                temp.outputStream().buffered().use { output ->
                    copyAndHash(input, output)
                }
            } ?: error("ContentResolver returned no readable stream")

            if (copiedHash != normalizedExpected) {
                temp.delete()
                return QuarantineRecord(
                    id = normalizedExpected,
                    originalUri = uri.toString(),
                    originalDisplayName = displayName,
                    sha256 = normalizedExpected,
                    vaultFileName = targetName,
                    createdAtEpochMs = createdAt,
                    originalRemovalRequested = removeOriginalAfterVerifiedCopy,
                    originalRemoved = false,
                    outcome = QuarantineOutcome.FAILED,
                    detail = "Vault copy hash mismatch; original was not modified.",
                )
            }

            if (target.exists()) {
                val existingHash = hashFile(target)
                if (existingHash != normalizedExpected) {
                    temp.delete()
                    error("Existing quarantine object failed hash verification")
                }
                temp.delete()
            } else if (!temp.renameTo(target)) {
                temp.inputStream().use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
                temp.delete()
                check(hashFile(target) == normalizedExpected) { "Final quarantine copy failed hash verification" }
            }

            val originalRemoved = if (removeOriginalAfterVerifiedCopy && supportsDelete(uri)) {
                runCatching { DocumentsContract.deleteDocument(resolver, uri) }.getOrDefault(false)
            } else {
                false
            }

            val outcome = if (originalRemoved) {
                QuarantineOutcome.CONTAINED
            } else {
                QuarantineOutcome.VAULT_COPY_ONLY
            }

            QuarantineRecord(
                id = normalizedExpected,
                originalUri = uri.toString(),
                originalDisplayName = displayName,
                sha256 = normalizedExpected,
                vaultFileName = targetName,
                createdAtEpochMs = createdAt,
                originalRemovalRequested = removeOriginalAfterVerifiedCopy,
                originalRemoved = originalRemoved,
                outcome = outcome,
                detail = when (outcome) {
                    QuarantineOutcome.CONTAINED -> "Verified vault copy created and original document deleted."
                    QuarantineOutcome.VAULT_COPY_ONLY -> "Verified vault copy created; original document remains accessible at its source."
                    QuarantineOutcome.FAILED -> error("unreachable")
                },
            )
        } catch (error: Throwable) {
            temp.delete()
            QuarantineRecord(
                id = normalizedExpected,
                originalUri = uri.toString(),
                originalDisplayName = displayName,
                sha256 = normalizedExpected,
                vaultFileName = targetName,
                createdAtEpochMs = createdAt,
                originalRemovalRequested = removeOriginalAfterVerifiedCopy,
                originalRemoved = false,
                outcome = QuarantineOutcome.FAILED,
                detail = error.message ?: error::class.java.simpleName,
            )
        }
    }

    fun restore(
        record: QuarantineRecord,
        destinationUri: Uri,
        removeVaultCopyAfterVerification: Boolean = true,
    ): RestoreResult {
        val expected = normalizeSha256(record.sha256)
        val source = File(vaultDir, record.vaultFileName)
        if (!source.isFile) {
            return RestoreResult(
                outcome = RestoreOutcome.FAILED,
                sha256 = null,
                vaultCopyRemoved = false,
                detail = "Quarantine object no longer exists.",
            )
        }
        if (hashFile(source) != expected) {
            return RestoreResult(
                outcome = RestoreOutcome.HASH_MISMATCH,
                sha256 = null,
                vaultCopyRemoved = false,
                detail = "Quarantine object failed integrity verification before restore.",
            )
        }

        return try {
            resolver.openOutputStream(destinationUri, "wt")?.use { output ->
                FileInputStream(source).use { input -> input.copyTo(output) }
            } ?: error("ContentResolver returned no writable stream")

            val restoredHash = resolver.openInputStream(destinationUri)?.use { input ->
                hashStream(input)
            } ?: error("Cannot verify restored destination")

            if (restoredHash != expected) {
                RestoreResult(
                    outcome = RestoreOutcome.HASH_MISMATCH,
                    sha256 = restoredHash,
                    vaultCopyRemoved = false,
                    detail = "Restored destination hash does not match quarantine object; vault copy retained.",
                )
            } else {
                val vaultRemoved = if (removeVaultCopyAfterVerification) source.delete() else false
                RestoreResult(
                    outcome = RestoreOutcome.RESTORED,
                    sha256 = restoredHash,
                    vaultCopyRemoved = vaultRemoved,
                    detail = "Restore verified by SHA-256.",
                )
            }
        } catch (error: Throwable) {
            RestoreResult(
                outcome = RestoreOutcome.FAILED,
                sha256 = null,
                vaultCopyRemoved = false,
                detail = error.message ?: error::class.java.simpleName,
            )
        }
    }

    fun listRecords(): List<String> = vaultDir.listFiles()
        .orEmpty()
        .filter(File::isFile)
        .map(File::getName)
        .sorted()

    private fun supportsDelete(uri: Uri): Boolean {
        if (!DocumentsContract.isDocumentUri(appContext, uri)) return false
        val projection = arrayOf(DocumentsContract.Document.COLUMN_FLAGS)
        return runCatching {
            resolver.query(uri, projection, null, null, null)?.use { cursor ->
                if (!cursor.moveToFirst()) return@use false
                val index = cursor.getColumnIndex(DocumentsContract.Document.COLUMN_FLAGS)
                if (index < 0 || cursor.isNull(index)) return@use false
                val flags = cursor.getInt(index)
                flags and DocumentsContract.Document.FLAG_SUPPORTS_DELETE != 0
            } ?: false
        }.getOrDefault(false)
    }

    private fun copyAndHash(input: java.io.InputStream, output: java.io.OutputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            total += read
            if (total > maxBytes) error("Artifact exceeds quarantine limit of $maxBytes bytes")
            output.write(buffer, 0, read)
            digest.update(buffer, 0, read)
        }
        output.flush()
        return digest.digest().toHex()
    }

    private fun hashFile(file: File): String = FileInputStream(file).use(::hashStream)

    private fun hashStream(input: java.io.InputStream): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read <= 0) break
            total += read
            if (total > maxBytes) error("Artifact exceeds verification limit of $maxBytes bytes")
            digest.update(buffer, 0, read)
        }
        return digest.digest().toHex()
    }

    private fun normalizeSha256(value: String): String {
        val normalized = value.trim().lowercase()
        require(normalized.length == 64 && normalized.all { it in '0'..'9' || it in 'a'..'f' }) {
            "Expected SHA-256 must be 64 lowercase/uppercase hexadecimal characters"
        }
        return normalized
    }

    private fun safeExtension(displayName: String): String {
        val extension = displayName.substringAfterLast('.', "")
            .lowercase()
            .takeIf { it.length in 1..10 && it.all(Char::isLetterOrDigit) }
        return extension?.let { ".$it" } ?: ".bin"
    }

    private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte) }
}
