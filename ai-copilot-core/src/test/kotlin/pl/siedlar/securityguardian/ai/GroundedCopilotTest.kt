package pl.siedlar.securityguardian.ai

import pl.siedlar.securityguardian.command.SecurityAction
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GroundedCopilotTest {
    @Test
    fun offlinePolishFullScanRoutesWithoutProvider() {
        val copilot = GroundedCopilot(requestIdFactory = { "req-1" })
        val result = copilot.plan(
            "Zeskanuj telefon",
            CopilotContext(emptyList(), setOf(SecurityAction.RUN_FULL_SCAN)),
        )
        assertEquals(SecurityAction.RUN_FULL_SCAN, result.proposedCommand?.action)
        assertTrue(result.fallbackUsed)
    }

    @Test
    fun offlineUrlCommandCarriesOnlyExtractedUrl() {
        val copilot = GroundedCopilot(requestIdFactory = { "req-2" })
        val result = copilot.plan(
            "Sprawdź link https://example.com/a?b=1 proszę",
            CopilotContext(emptyList(), setOf(SecurityAction.CHECK_URL)),
        )
        assertEquals("https://example.com/a?b=1", result.proposedCommand?.arguments?.get("url"))
    }

    @Test
    fun unknownCommandDoesNothingWhenProviderUnavailable() {
        val result = GroundedCopilot().plan(
            "Powiedz mi coś o bezpieczeństwie",
            CopilotContext(emptyList(), SecurityAction.entries.toSet()),
        )
        assertNull(result.proposedCommand)
        assertTrue("AI_PROVIDER_UNAVAILABLE" in result.warnings)
    }

    @Test
    fun providerCannotReferenceUnknownDeviceFact() {
        val provider = object : AIProvider {
            override val id = "test"
            override fun respond(request: AiProviderRequest) = AiProviderResponse(
                explanation = "Mikrofon był aktywny.",
                referencedFactIds = setOf("invented-mic-fact"),
            )
        }
        val result = GroundedCopilot(provider = provider).plan(
            "Czy ktoś mnie obserwuje?",
            CopilotContext(
                facts = listOf(SecurityFact("real-fact", "privacy", "Brak danych o aktywnym mikrofonie", emptyList(), 1L)),
                allowedActions = emptySet(),
            ),
        )
        assertNull(result.proposedCommand)
        assertTrue(result.warnings.single().startsWith("UNGROUNDED_FACT_REFERENCE"))
    }

    @Test
    fun providerCannotProposeActionOutsideAllowlist() {
        val provider = object : AIProvider {
            override val id = "test"
            override fun respond(request: AiProviderRequest) = AiProviderResponse(
                explanation = "Proponuję reset.",
                referencedFactIds = emptySet(),
                proposedAction = ProposedSecurityAction(SecurityAction.FACTORY_RESET, emptyMap()),
            )
        }
        val result = GroundedCopilot(provider = provider).plan(
            "Napraw wszystko",
            CopilotContext(emptyList(), setOf(SecurityAction.RUN_FULL_SCAN)),
        )
        assertNull(result.proposedCommand)
        assertTrue(result.warnings.single().startsWith("PROPOSED_ACTION_NOT_ALLOWED"))
    }

    @Test
    fun providerGroundedProposalBecomesClosedCommand() {
        val provider = object : AIProvider {
            override val id = "test"
            override fun respond(request: AiProviderRequest) = AiProviderResponse(
                explanation = "Zablokuj domenę wskazaną w potwierdzonym incydencie.",
                referencedFactIds = setOf("ioc-1"),
                proposedAction = ProposedSecurityAction(
                    SecurityAction.BLOCK_DOMAIN,
                    mapOf("domain" to "bad.example"),
                ),
            )
        }
        val result = GroundedCopilot(provider = provider, requestIdFactory = { "req-3" }).plan(
            "Zabezpiecz mnie przed tym",
            CopilotContext(
                facts = listOf(SecurityFact("ioc-1", "network", "bad.example jest w lokalnym IOC", listOf("hash-list-v1"), 1L)),
                allowedActions = setOf(SecurityAction.BLOCK_DOMAIN),
            ),
        )
        assertNotNull(result.proposedCommand)
        assertEquals(SecurityAction.BLOCK_DOMAIN, result.proposedCommand.action)
        assertEquals(listOf("ioc-1"), result.groundedFacts.map(SecurityFact::id))
    }
}
