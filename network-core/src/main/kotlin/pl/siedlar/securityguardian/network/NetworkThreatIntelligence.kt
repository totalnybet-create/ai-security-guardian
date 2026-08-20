package pl.siedlar.securityguardian.network

interface NetworkThreatProvider {
    val id: String
    fun lookup(flow: NetworkFlow): ThreatEvidence?
}

class CompositeNetworkThreatEngine(
    private val providers: List<NetworkThreatProvider>,
) {
    fun lookup(flow: NetworkFlow): List<ThreatEvidence> = providers.mapNotNull { provider ->
        runCatching { provider.lookup(flow) }
            .getOrElse { error ->
                ThreatEvidence(
                    source = provider.id,
                    verdict = ThreatVerdict.UNKNOWN,
                    confidence = 0,
                    reason = "Provider unavailable: ${error::class.java.simpleName}",
                )
            }
    }
}
