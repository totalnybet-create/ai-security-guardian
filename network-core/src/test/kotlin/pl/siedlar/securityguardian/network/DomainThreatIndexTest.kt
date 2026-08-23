package pl.siedlar.securityguardian.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DomainThreatIndexTest {
    @Test
    fun maliciousSuffixMatchesSubdomainButNotLookalike() {
        val index = DomainThreatIndex(
            listOf(
                DomainIoc(
                    id = "c2-1",
                    domain = "bad.example",
                    verdict = ThreatVerdict.MALICIOUS,
                    confidence = 99,
                    source = "unit-test",
                ),
            ),
        )

        assertEquals("c2-1", index.lookup("api.bad.example", 1_000L).single().id)
        assertTrue(index.lookup("evil-bad.example", 1_000L).isEmpty())
    }

    @Test
    fun expiredIocDoesNotBlock() {
        val provider = DomainIocThreatProvider(
            id = "local-ioc",
            index = DomainThreatIndex(
                listOf(
                    DomainIoc(
                        id = "expired",
                        domain = "expired.example",
                        verdict = ThreatVerdict.MALICIOUS,
                        confidence = 100,
                        source = "unit-test",
                        expiresAtEpochMs = 2_000L,
                    ),
                ),
            ),
            now = { 2_000L },
        )

        assertNull(provider.lookup(flow("expired.example")))
    }

    @Test
    fun maliciousWinsOverCleanForSameHost() {
        val provider = DomainIocThreatProvider(
            id = "local-ioc",
            index = DomainThreatIndex(
                listOf(
                    DomainIoc("clean", "mixed.example", ThreatVerdict.CLEAN, 100, "clean-source"),
                    DomainIoc("bad", "mixed.example", ThreatVerdict.MALICIOUS, 91, "malware-source"),
                ),
            ),
            now = { 1_000L },
        )

        val evidence = provider.lookup(flow("mixed.example"))
        requireNotNull(evidence)
        assertEquals(ThreatVerdict.MALICIOUS, evidence.verdict)
        assertEquals(91, evidence.confidence)
    }

    @Test
    fun idnCanonicalizationMatchesEquivalentHost() {
        val index = DomainThreatIndex(
            listOf(
                DomainIoc(
                    id = "idn",
                    domain = "bücher.example",
                    verdict = ThreatVerdict.SUSPICIOUS,
                    confidence = 70,
                    source = "unit-test",
                    includeSubdomains = false,
                ),
            ),
        )

        assertEquals("idn", index.lookup("xn--bcher-kva.example.", 1_000L).single().id)
    }

    private fun flow(host: String) = NetworkFlow(
        appPackage = null,
        destinationHost = host,
        destinationIp = "203.0.113.9",
        destinationPort = 443,
        protocol = NetworkProtocol.TCP,
    )
}
