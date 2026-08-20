package pl.siedlar.securityguardian.audit

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject
import pl.siedlar.securityguardian.core.AuditEvent
import pl.siedlar.securityguardian.core.AuditSink
import java.io.File

class JsonlAuditLogger(
    context: Context,
) : AuditSink {
    private val file = File(context.filesDir, "security-audit.jsonl")

    override fun append(event: AuditEvent) {
        val json = JSONObject()
            .put("timestamp", event.timestampEpochMs)
            .put("event", event.event)
            .put("source", event.source)
            .put("risk", event.risk.name)
            .put("evidence", JSONArray(event.evidence))
            .put("action", event.action)
            .put("result", event.result)
            .put("verification", event.verification)
            .toString()

        synchronized(PROCESS_FILE_LOCK) {
            file.appendText(json + "\n", Charsets.UTF_8)
        }
    }

    fun logFile(): File = file

    private companion object {
        val PROCESS_FILE_LOCK = Any()
    }
}
