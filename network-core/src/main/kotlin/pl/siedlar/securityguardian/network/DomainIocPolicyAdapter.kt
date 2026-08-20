package pl.siedlar.securityguardian.network

class DomainIocPolicyAdapter(
    private val maliciousBlockThreshold: Int = 80,
    private val suspiciousAskThreshold: Int = 60,
    private val blockPriority: Int = 900,
    private val askPriority: Int = 800,
) {
    init {
        require(maliciousBlockThreshold in 1..100)
        require(suspiciousAskThreshold in 1..100)
    }

    fun toRules(
        entries: List<DomainIoc>,
        nowEpochMs: Long,
    ): List<NetworkRule> = entries
        .asSequence()
        .filter { ioc -> ioc.expiresAtEpochMs == null || ioc.expiresAtEpochMs > nowEpochMs }
        .mapNotNull { ioc ->
            val action = when {
                ioc.verdict == ThreatVerdict.MALICIOUS && ioc.confidence >= maliciousBlockThreshold -> NetworkAction.BLOCK
                ioc.verdict == ThreatVerdict.SUSPICIOUS && ioc.confidence >= suspiciousAskThreshold -> NetworkAction.ASK
                else -> return@mapNotNull null
            }
            NetworkRule(
                id = "ioc:${ioc.id}",
                action = action,
                domainSuffix = ioc.domain,
                priority = if (action == NetworkAction.BLOCK) blockPriority else askPriority,
                expiresAtEpochMs = ioc.expiresAtEpochMs,
            )
        }
        .sortedWith(compareByDescending<NetworkRule> { it.priority }.thenBy { it.id })
        .toList()
}
