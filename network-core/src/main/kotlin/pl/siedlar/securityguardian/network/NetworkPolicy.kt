package pl.siedlar.securityguardian.network

import java.net.IDN
import java.util.Locale

enum class NetworkAction {
    ALLOW,
    BLOCK,
    ASK,
    TEMPORARY_ALLOW,
}

enum class NetworkProtocol {
    TCP,
    UDP,
    ICMP,
    OTHER,
}

enum class ThreatVerdict {
    CLEAN,
    UNKNOWN,
    SUSPICIOUS,
    MALICIOUS,
}

data class NetworkFlow(
    val appPackage: String,
    val destinationHost: String?,
    val destinationIp: String?,
    val destinationPort: Int?,
    val protocol: NetworkProtocol,
) {
    init {
        require(appPackage.isNotBlank())
        destinationPort?.let { require(it in 1..65535) }
    }
}

data class NetworkRule(
    val id: String,
    val action: NetworkAction,
    val appPackage: String? = null,
    val domainSuffix: String? = null,
    val destinationIp: String? = null,
    val destinationPort: Int? = null,
    val protocol: NetworkProtocol? = null,
    val priority: Int = 0,
    val expiresAtEpochMs: Long? = null,
    val enabled: Boolean = true,
) {
    init {
        require(id.isNotBlank())
        destinationPort?.let { require(it in 1..65535) }
        if (action == NetworkAction.TEMPORARY_ALLOW) {
            require(expiresAtEpochMs != null) { "TEMPORARY_ALLOW requires an expiry" }
        }
    }
}

data class ThreatEvidence(
    val source: String,
    val verdict: ThreatVerdict,
    val confidence: Int,
    val reason: String,
) {
    init {
        require(source.isNotBlank())
        require(confidence in 0..100)
    }
}

data class NetworkDecision(
    val action: NetworkAction,
    val matchedRuleId: String?,
    val reason: String,
    val threatEvidence: List<ThreatEvidence>,
)

class NetworkPolicyEngine(
    private val maliciousConfidenceThreshold: Int = 80,
    private val suspiciousConfidenceThreshold: Int = 60,
) {
    init {
        require(maliciousConfidenceThreshold in 1..100)
        require(suspiciousConfidenceThreshold in 1..100)
    }

    fun decide(
        flow: NetworkFlow,
        rules: List<NetworkRule>,
        threatEvidence: List<ThreatEvidence>,
        nowEpochMs: Long,
    ): NetworkDecision {
        val activeRules = rules
            .asSequence()
            .filter(NetworkRule::enabled)
            .filter { rule -> rule.expiresAtEpochMs == null || rule.expiresAtEpochMs > nowEpochMs }
            .filter { rule -> matches(rule, flow) }
            .sortedWith(compareByDescending<NetworkRule> { it.priority }.thenBy { it.id })
            .toList()

        val explicitBlock = activeRules.firstOrNull { it.action == NetworkAction.BLOCK }
        if (explicitBlock != null) {
            return NetworkDecision(
                action = NetworkAction.BLOCK,
                matchedRuleId = explicitBlock.id,
                reason = "Matched explicit BLOCK rule.",
                threatEvidence = threatEvidence,
            )
        }

        val malicious = threatEvidence
            .filter { it.verdict == ThreatVerdict.MALICIOUS && it.confidence >= maliciousConfidenceThreshold }
            .maxByOrNull(ThreatEvidence::confidence)
        if (malicious != null) {
            return NetworkDecision(
                action = NetworkAction.BLOCK,
                matchedRuleId = null,
                reason = "High-confidence malicious network reputation: ${malicious.source}.",
                threatEvidence = threatEvidence,
            )
        }

        val explicitDecision = activeRules.firstOrNull {
            it.action == NetworkAction.ALLOW ||
                it.action == NetworkAction.TEMPORARY_ALLOW ||
                it.action == NetworkAction.ASK
        }
        if (explicitDecision != null) {
            return NetworkDecision(
                action = explicitDecision.action,
                matchedRuleId = explicitDecision.id,
                reason = "Matched explicit ${explicitDecision.action} rule.",
                threatEvidence = threatEvidence,
            )
        }

        val suspicious = threatEvidence
            .filter { it.verdict == ThreatVerdict.SUSPICIOUS && it.confidence >= suspiciousConfidenceThreshold }
            .maxByOrNull(ThreatEvidence::confidence)
        if (suspicious != null) {
            return NetworkDecision(
                action = NetworkAction.ASK,
                matchedRuleId = null,
                reason = "Suspicious destination requires user/policy decision: ${suspicious.source}.",
                threatEvidence = threatEvidence,
            )
        }

        return NetworkDecision(
            action = NetworkAction.ALLOW,
            matchedRuleId = null,
            reason = if (threatEvidence.any { it.verdict == ThreatVerdict.UNKNOWN }) {
                "No blocking evidence. Optional reputation is unknown; fail-open to preserve connectivity."
            } else {
                "No blocking rule or threat evidence matched."
            },
            threatEvidence = threatEvidence,
        )
    }

    private fun matches(rule: NetworkRule, flow: NetworkFlow): Boolean {
        if (rule.appPackage != null && rule.appPackage != flow.appPackage) return false
        if (rule.destinationIp != null && rule.destinationIp != flow.destinationIp) return false
        if (rule.destinationPort != null && rule.destinationPort != flow.destinationPort) return false
        if (rule.protocol != null && rule.protocol != flow.protocol) return false

        val rawSuffix = rule.domainSuffix
        if (rawSuffix != null) {
            val suffix = rawSuffix.normalizeHost() ?: return false
            val host = flow.destinationHost?.normalizeHost() ?: return false
            if (host != suffix && !host.endsWith(".$suffix")) return false
        }
        return true
    }

    private fun String.normalizeHost(): String? = runCatching {
        val trimmed = trim().trimEnd('.')
        IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES)
            .lowercase(Locale.ROOT)
            .takeIf(String::isNotBlank)
    }.getOrNull()
}
