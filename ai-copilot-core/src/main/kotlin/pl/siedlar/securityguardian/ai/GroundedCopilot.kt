package pl.siedlar.securityguardian.ai

import pl.siedlar.securityguardian.command.CommandSource
import pl.siedlar.securityguardian.command.SecurityCommandRequest
import java.util.UUID

class GroundedCopilot(
    private val localRouter: LocalSecurityIntentRouter = LocalSecurityIntentRouter(),
    private val provider: AIProvider? = null,
    private val requestIdFactory: () -> String = { UUID.randomUUID().toString() },
) {
    fun plan(
        userText: String,
        context: CopilotContext,
    ): CopilotTurnResult {
        val boundedText = userText.trim().take(MAX_USER_TEXT_CHARS)
        if (boundedText.isBlank()) {
            return CopilotTurnResult(
                explanation = "Nie otrzymałem polecenia do analizy.",
                groundedFacts = emptyList(),
                proposedCommand = null,
                providerId = null,
                fallbackUsed = true,
                warnings = listOf("EMPTY_INPUT"),
            )
        }

        val localProposal = localRouter.route(boundedText, context.allowedActions)
        if (localProposal != null) {
            return CopilotTurnResult(
                explanation = localExplanation(localProposal),
                groundedFacts = emptyList(),
                proposedCommand = localProposal.toRequest(),
                providerId = null,
                fallbackUsed = true,
                warnings = emptyList(),
            )
        }

        val activeProvider = provider ?: return CopilotTurnResult(
            explanation = "To polecenie wymaga rozszerzonej interpretacji AI, ale żaden provider AI nie jest obecnie aktywny. Nie wykonano żadnej akcji.",
            groundedFacts = emptyList(),
            proposedCommand = null,
            providerId = null,
            fallbackUsed = true,
            warnings = listOf("AI_PROVIDER_UNAVAILABLE"),
        )

        val response = runCatching {
            activeProvider.respond(
                AiProviderRequest(
                    userText = boundedText,
                    facts = context.facts,
                    allowedActions = context.allowedActions,
                ),
            )
        }.getOrElse { error ->
            return CopilotTurnResult(
                explanation = "Provider AI nie odpowiedział. Nie wykonano żadnej akcji.",
                groundedFacts = emptyList(),
                proposedCommand = null,
                providerId = activeProvider.id,
                fallbackUsed = true,
                warnings = listOf("AI_PROVIDER_FAILED:${error::class.java.simpleName}"),
            )
        }

        val factsById = context.facts.associateBy(SecurityFact::id)
        val unknownFactIds = response.referencedFactIds - factsById.keys
        if (unknownFactIds.isNotEmpty()) {
            return CopilotTurnResult(
                explanation = "Odpowiedź AI odwołała się do danych, których Security Engine nie dostarczył. Odpowiedź została odrzucona i nie wykonano żadnej akcji.",
                groundedFacts = emptyList(),
                proposedCommand = null,
                providerId = activeProvider.id,
                fallbackUsed = false,
                warnings = listOf("UNGROUNDED_FACT_REFERENCE:${unknownFactIds.sorted().joinToString() }"),
            )
        }

        val proposed = response.proposedAction
        if (proposed != null && proposed.action !in context.allowedActions) {
            return CopilotTurnResult(
                explanation = response.explanation.take(MAX_EXPLANATION_CHARS),
                groundedFacts = response.referencedFactIds.mapNotNull(factsById::get),
                proposedCommand = null,
                providerId = activeProvider.id,
                fallbackUsed = false,
                warnings = listOf("PROPOSED_ACTION_NOT_ALLOWED:${proposed.action}"),
            )
        }

        val command = proposed?.let {
            runCatching { it.toRequest() }.getOrNull()
        }

        return CopilotTurnResult(
            explanation = response.explanation.take(MAX_EXPLANATION_CHARS),
            groundedFacts = response.referencedFactIds.mapNotNull(factsById::get),
            proposedCommand = command,
            providerId = activeProvider.id,
            fallbackUsed = false,
            warnings = if (proposed != null && command == null) listOf("INVALID_PROPOSED_ARGUMENTS") else emptyList(),
        )
    }

    private fun ProposedSecurityAction.toRequest(): SecurityCommandRequest = SecurityCommandRequest(
        requestId = requestIdFactory(),
        action = action,
        arguments = arguments,
        source = CommandSource.AI,
    )

    private fun localExplanation(proposal: ProposedSecurityAction): String = when (proposal.action) {
        pl.siedlar.securityguardian.command.SecurityAction.RUN_FULL_SCAN -> "Rozpoznano polecenie pełnego skanu. Security Engine wykona tylko warstwy dostępne na aktualnym poziomie uprawnień."
        pl.siedlar.securityguardian.command.SecurityAction.CHECK_PRIVACY -> "Rozpoznano kontrolę prywatności. Wynik musi pochodzić z Security Engine, nie z modelu językowego."
        pl.siedlar.securityguardian.command.SecurityAction.CHECK_URL -> "Rozpoznano sprawdzenie linku. Link zostanie oceniony przez lokalny URL Guard przed ewentualnym otwarciem."
        pl.siedlar.securityguardian.command.SecurityAction.BLOCK_DOMAIN -> "Rozpoznano blokadę domeny. Operacja przejdzie przez Policy Engine i aktualny DNS Guard."
        pl.siedlar.securityguardian.command.SecurityAction.ALLOW_DOMAIN_TEMPORARILY -> "Rozpoznano tymczasowe zezwolenie domenie. Czas zezwolenia pozostaje jawnie ograniczony."
        pl.siedlar.securityguardian.command.SecurityAction.CHECK_APP -> "Rozpoznano kontrolę aplikacji. Wynik zostanie zbudowany z danych inspektora aplikacji."
        else -> "Rozpoznano bezpieczne lokalne polecenie Security Engine."
    }

    private companion object {
        const val MAX_USER_TEXT_CHARS = 8_192
        const val MAX_EXPLANATION_CHARS = 8_192
    }
}
