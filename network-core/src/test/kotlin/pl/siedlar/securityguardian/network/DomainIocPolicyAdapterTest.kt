package pl.siedlar.securityguardian.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DomainIocPolicyAdapterTest {
    private val adapter = DomainIocPolicyAdapter()

    @Test
    fun maliciousHighConfidenceBlocks() {
        val rules = adapter.toRules(
            listOf(ioc("m", ThreatVerdict.MALICIOUS, 90)),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.BLOCK, rules.single().action)
    }

    @Test
    fun suspiciousHighConfidenceAsks() {
        val rules = adapter.toRules(
            listOf(ioc("s", ThreatVerdict.SUSPICIOUS, 70)),
            nowEpochMs = 1_000L,
        )
        assertEquals(NetworkAction.ASK, rules.single().action)
    }

    @Test
    fun cleanUnknownAndWeakEvidenceDoNotCreateRules() {
        val rules = adapter.toRules(
            listOf(
                ioc("clean", ThreatVerdict.CLEAN, 100),
                ioc("unknown", ThreatVerdict.UNKNOWN, 100),
                ioc("weak-m", ThreatVerdict.MALICIOUS, 79),
                ioc("weak-s", ThreatVerdict.SUSPICIOUS, 59),
            ),
            nowEpochMs = 1_000L,
        )
        assertTrue(rules.isEmpty())
    }

    @Test
    fun expiredEvidenceIsIgnored() {
        val expired = ioc("expired", ThreatVerdict.MALICIOUS, 100).copy(expiresAtEpochMs = 1_000L)
        assertTrue(adapter.toRules(listOf(expired), nowEpochMs = 1_000L).isEmpty())
    }

    private fun ioc(id: String, verdict: ThreatVerdict, confidence: Int) = DomainIoc(
        id = id,
        domain = "$id.example",
        verdict = verdict,
        confidence = confidence,
        source = "unit-test",
    )
}
