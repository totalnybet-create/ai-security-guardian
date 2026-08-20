package pl.siedlar.securityguardian.network

import java.net.IDN
import java.util.Locale

data class DomainIoc(
    val id: String,
    val domain: String,
    val verdict: ThreatVerdict,
    val confidence: Int,
    val source: String,
    val includeSubdomains: Boolean = true,
    val expiresAtEpochMs: Long? = null,
) {
    init {
        require(id.isNotBlank())
        require(domain.isNotBlank())
        require(source.isNotBlank())
        require(confidence in 0..100)
    }
}

class DomainThreatIndex(
    entries: List<DomainIoc>,
) {
    private val normalizedEntries = entries.mapNotNull { entry ->
        normalizeHost(entry.domain)?.let { normalized -> NormalizedIoc(entry, normalized) }
    }

    fun lookup(host: String, nowEpochMs: Long): List<DomainIoc> {
        val normalizedHost = normalizeHost(host) ?: return emptyList()
        return normalizedEntries
            .asSequence()
            .filter { item -> item.ioc.expiresAtEpochMs == null || item.ioc.expiresAtEpochMs > nowEpochMs }
            .filter { item ->
                normalizedHost == item.domain ||
                    (item.ioc.includeSubdomains && normalizedHost.endsWith(".${item.domain}"))
            }
            .sortedWith(
                compareByDescending<NormalizedIoc> { verdictRank(it.ioc.verdict) }
                    .thenByDescending { it.ioc.confidence }
                    .thenBy { it.ioc.id },
            )
            .map(NormalizedIoc::ioc)
            .toList()
    }

    private data class NormalizedIoc(
        val ioc: DomainIoc,
        val domain: String,
    )

    private companion object {
        fun normalizeHost(value: String): String? = runCatching {
            IDN.toASCII(value.trim().trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
                .lowercase(Locale.ROOT)
                .takeIf { host ->
                    host.isNotBlank() &&
                        host.length <= 253 &&
                        host.split('.').all { label -> label.isNotBlank() && label.length <= 63 }
                }
        }.getOrNull()

        fun verdictRank(verdict: ThreatVerdict): Int = when (verdict) {
            ThreatVerdict.MALICIOUS -> 4
            ThreatVerdict.SUSPICIOUS -> 3
            ThreatVerdict.UNKNOWN -> 2
            ThreatVerdict.CLEAN -> 1
        }
    }
}

class DomainIocThreatProvider(
    override val id: String,
    private val index: DomainThreatIndex,
    private val now: () -> Long = { System.currentTimeMillis() },
) : NetworkThreatProvider {
    init {
        require(id.isNotBlank())
    }

    override fun lookup(flow: NetworkFlow): ThreatEvidence? {
        val host = flow.destinationHost ?: return null
        val match = index.lookup(host, now()).firstOrNull() ?: return null
        return ThreatEvidence(
            source = "$id:${match.source}",
            verdict = match.verdict,
            confidence = match.confidence,
            reason = "Matched local domain IOC ${match.id}.",
        )
    }
}
