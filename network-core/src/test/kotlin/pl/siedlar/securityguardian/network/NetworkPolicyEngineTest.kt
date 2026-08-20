package pl.siedlar.securityguardian.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class NetworkPolicyEngineTest {
    private val engine = NetworkPolicyEngine()
    private val flow = NetworkFlow(
        appPackage = "test.app",
        destinationHost = "api.example.com",
        destinationIp = "203.0.113.10",
        destinationPort = 443,
        protocol = NetworkProtocol.TCP,
    )

    @Test
    fun unknownReputationFailsOpen() {
        val decision = engine.decide(
            flow = flow,
            rules = emptyList(),
            threatEvidence = listOf(
                ThreatEvidence("provider-down", ThreatVerdict.UNKNOWN, 0, "Provider unavailable"),
            ),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.ALLOW, decision.action)
        assertTrue(decision.reason.contains("fail-open"))
    }

    @Test
    fun providerFailureBecomesUnknownEvidence() {
        val threatEngine = CompositeNetworkThreatEngine(
            listOf(
                object : NetworkThreatProvider {
                    override val id: String = "broken-provider"
                    override fun lookup(flow: NetworkFlow): ThreatEvidence = error("offline")
                },
            ),
        )
        val evidence = threatEngine.lookup(flow)
        assertEquals(1, evidence.size)
        assertEquals(ThreatVerdict.UNKNOWN, evidence.single().verdict)
        assertEquals(NetworkAction.ALLOW, engine.decide(flow, emptyList(), evidence, 1_000L).action)
    }

    @Test
    fun maliciousReputationOverridesAllowRule() {
        val decision = engine.decide(
            flow = flow,
            rules = listOf(
                NetworkRule(
                    id = "allow-example",
                    action = NetworkAction.ALLOW,
                    domainSuffix = "example.com",
                    priority = 100,
                ),
            ),
            threatEvidence = listOf(
                ThreatEvidence("local-ioc", ThreatVerdict.MALICIOUS, 99, "Known C2"),
            ),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.BLOCK, decision.action)
    }

    @Test
    fun explicitBlockWins() {
        val decision = engine.decide(
            flow = flow,
            rules = listOf(
                NetworkRule(id = "allow", action = NetworkAction.ALLOW, appPackage = "test.app", priority = 100),
                NetworkRule(id = "block", action = NetworkAction.BLOCK, domainSuffix = "example.com", priority = 1),
            ),
            threatEvidence = emptyList(),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.BLOCK, decision.action)
        assertEquals("block", decision.matchedRuleId)
    }

    @Test
    fun temporaryAllowExpires() {
        val rule = NetworkRule(
            id = "temp",
            action = NetworkAction.TEMPORARY_ALLOW,
            appPackage = "test.app",
            expiresAtEpochMs = 2_000L,
        )

        assertEquals(
            NetworkAction.TEMPORARY_ALLOW,
            engine.decide(flow, listOf(rule), emptyList(), 1_500L).action,
        )
        assertEquals(
            NetworkAction.ALLOW,
            engine.decide(flow, listOf(rule), emptyList(), 2_000L).action,
        )
    }

    @Test
    fun domainSuffixDoesNotMatchLookalike() {
        val lookalikeFlow = flow.copy(destinationHost = "evil-example.com")
        val decision = engine.decide(
            flow = lookalikeFlow,
            rules = listOf(NetworkRule(id = "block", action = NetworkAction.BLOCK, domainSuffix = "example.com")),
            threatEvidence = emptyList(),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.ALLOW, decision.action)
    }

    @Test
    fun domainCanonicalizationHandlesCaseTrailingDotAndIdn() {
        val caseFlow = flow.copy(destinationHost = "API.Example.COM.")
        assertEquals(
            NetworkAction.BLOCK,
            engine.decide(
                caseFlow,
                listOf(NetworkRule(id = "case", action = NetworkAction.BLOCK, domainSuffix = "example.com.")),
                emptyList(),
                1_000L,
            ).action,
        )

        val idnFlow = flow.copy(destinationHost = "api.xn--bcher-kva.example")
        assertEquals(
            NetworkAction.BLOCK,
            engine.decide(
                idnFlow,
                listOf(NetworkRule(id = "idn", action = NetworkAction.BLOCK, domainSuffix = "bücher.example")),
                emptyList(),
                1_000L,
            ).action,
        )
    }

    @Test
    fun suspiciousReputationAsksInsteadOfSilentlyBlocking() {
        val decision = engine.decide(
            flow = flow,
            rules = emptyList(),
            threatEvidence = listOf(
                ThreatEvidence("heuristic", ThreatVerdict.SUSPICIOUS, 75, "New suspicious domain"),
            ),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.ASK, decision.action)
    }
}
