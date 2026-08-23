package pl.siedlar.securityguardian.ai

import pl.siedlar.securityguardian.command.SecurityAction
import pl.siedlar.securityguardian.command.SecurityCommandRequest

data class SecurityFact(
    val id: String,
    val category: String,
    val summary: String,
    val evidence: List<String>,
    val observedAtEpochMs: Long,
) {
    init {
        require(id.isNotBlank())
        require(category.isNotBlank())
        require(summary.isNotBlank())
        require(evidence.size <= 32)
    }
}

data class CopilotContext(
    val facts: List<SecurityFact>,
    val allowedActions: Set<SecurityAction>,
) {
    init {
        require(facts.map(SecurityFact::id).distinct().size == facts.size) { "Duplicate fact ids" }
    }
}

data class AiProviderRequest(
    val userText: String,
    val facts: List<SecurityFact>,
    val allowedActions: Set<SecurityAction>,
)

data class ProposedSecurityAction(
    val action: SecurityAction,
    val arguments: Map<String, String>,
)

data class AiProviderResponse(
    val explanation: String,
    val referencedFactIds: Set<String>,
    val proposedAction: ProposedSecurityAction? = null,
)

interface AIProvider {
    val id: String
    fun respond(request: AiProviderRequest): AiProviderResponse
}

data class CopilotTurnResult(
    val explanation: String,
    val groundedFacts: List<SecurityFact>,
    val proposedCommand: SecurityCommandRequest?,
    val providerId: String?,
    val fallbackUsed: Boolean,
    val warnings: List<String>,
)
