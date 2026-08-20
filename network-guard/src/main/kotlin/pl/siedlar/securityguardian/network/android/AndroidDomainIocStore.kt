package pl.siedlar.securityguardian.network.android

import android.content.Context
import org.json.JSONObject
import pl.siedlar.securityguardian.network.DomainIoc
import pl.siedlar.securityguardian.network.ThreatVerdict
import java.io.File

class AndroidDomainIocStore(
    context: Context,
    private val maxBytes: Long = 4L * 1024L * 1024L,
    private val maxEntries: Int = 50_000,
) {
    private val snapshotFile = File(context.applicationContext.filesDir, FILE_NAME)

    init {
        require(maxBytes in 1L..64L * 1024L * 1024L)
        require(maxEntries in 1..500_000)
    }

    fun load(): List<DomainIoc> {
        if (!snapshotFile.isFile) return emptyList()
        if (snapshotFile.length() > maxBytes) return emptyList()

        val results = ArrayList<DomainIoc>()
        snapshotFile.bufferedReader(Charsets.UTF_8).useLines { lines ->
            for (line in lines) {
                if (results.size >= maxEntries) break
                val trimmed = line.trim()
                if (trimmed.isBlank()) continue
                parseLine(trimmed)?.let(results::add)
            }
        }
        return results
    }

    private fun parseLine(line: String): DomainIoc? = runCatching {
        val json = JSONObject(line)
        val verdict = ThreatVerdict.valueOf(json.getString("verdict").uppercase())
        DomainIoc(
            id = json.getString("id").take(MAX_FIELD_CHARS),
            domain = json.getString("domain").take(MAX_DOMAIN_CHARS),
            verdict = verdict,
            confidence = json.getInt("confidence"),
            source = json.getString("source").take(MAX_FIELD_CHARS),
            includeSubdomains = json.optBoolean("includeSubdomains", true),
            expiresAtEpochMs = if (json.has("expiresAtEpochMs") && !json.isNull("expiresAtEpochMs")) {
                json.getLong("expiresAtEpochMs")
            } else {
                null
            },
        )
    }.getOrNull()

    companion object {
        const val FILE_NAME = "domain-ioc-v1.jsonl"
        private const val MAX_FIELD_CHARS = 256
        private const val MAX_DOMAIN_CHARS = 253
    }
}
