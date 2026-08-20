package pl.siedlar.securityguardian.command

interface SecurityCommandExecutor {
    val action: SecurityAction
    fun execute(request: SecurityCommandRequest): ExecutionResult
}

interface SecurityCommandVerifier {
    val action: SecurityAction
    fun verify(request: SecurityCommandRequest, execution: ExecutionResult): VerificationResult
}

fun interface CommandAuditSink {
    fun append(event: CommandAuditEvent)
}

interface ApprovalReplayGuard {
    fun consumeOnce(approvalId: String): Boolean
}

class InMemoryApprovalReplayGuard : ApprovalReplayGuard {
    private val consumed = mutableSetOf<String>()

    @Synchronized
    override fun consumeOnce(approvalId: String): Boolean = consumed.add(approvalId)
}

sealed interface BrokerResult {
    data class AwaitingHumanGate(
        val request: SecurityCommandRequest,
        val policy: ActionPolicy,
        val reason: String,
    ) : BrokerResult

    data class Denied(
        val request: SecurityCommandRequest,
        val decision: PolicyDecision,
    ) : BrokerResult

    data class Completed(
        val request: SecurityCommandRequest,
        val execution: ExecutionResult,
        val verification: VerificationResult,
    ) : BrokerResult
}

class SecurityCommandBroker(
    executors: List<SecurityCommandExecutor>,
    verifiers: List<SecurityCommandVerifier>,
    private val policyEngine: SecurityPolicyEngine = SecurityPolicyEngine(),
    private val auditSink: CommandAuditSink,
    private val replayGuard: ApprovalReplayGuard = InMemoryApprovalReplayGuard(),
    private val approvalTtlMs: Long = 2 * 60 * 1000L,
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    private val executorByAction = executors.associateBy(SecurityCommandExecutor::action)
    private val verifierByAction = verifiers.associateBy(SecurityCommandVerifier::action)

    init {
        require(approvalTtlMs in 1_000L..15 * 60 * 1000L)
        require(executorByAction.size == executors.size) { "Duplicate executor action" }
        require(verifierByAction.size == verifiers.size) { "Duplicate verifier action" }
    }

    fun submit(
        request: SecurityCommandRequest,
        capabilities: CapabilitySnapshot,
        approval: HumanApproval? = null,
    ): BrokerResult {
        val decision = policyEngine.evaluate(request, capabilities)

        if (decision.type == PolicyDecisionType.DENY_CAPABILITY ||
            decision.type == PolicyDecisionType.DENY_PRIVILEGE ||
            decision.type == PolicyDecisionType.DENY_POLICY
        ) {
            audit(
                request = request,
                decision = decision,
                executionResult = null,
                verified = null,
                detail = decision.reason,
            )
            return BrokerResult.Denied(request, decision)
        }

        if (decision.policy.humanGate != HumanGate.NONE) {
            val approvalError = validateApproval(request, decision.policy, approval)
            if (approvalError != null) {
                audit(
                    request = request,
                    decision = decision,
                    executionResult = null,
                    verified = null,
                    detail = approvalError,
                )
                return BrokerResult.AwaitingHumanGate(request, decision.policy, approvalError)
            }
        }

        val executor = executorByAction[request.action]
            ?: return deniedMissingImplementation(request, decision, "No executor registered for ${request.action}")
        val verifier = verifierByAction[request.action]
            ?: return deniedMissingImplementation(request, decision, "No verifier registered for ${request.action}")

        val execution = runCatching { executor.execute(request) }
            .getOrElse { error ->
                ExecutionResult(
                    success = false,
                    resultCode = "EXECUTOR_EXCEPTION",
                    detail = error.message ?: error::class.java.simpleName,
                )
            }

        val verification = if (execution.success) {
            runCatching { verifier.verify(request, execution) }
                .getOrElse { error ->
                    VerificationResult(
                        verified = false,
                        detail = "Verifier failed: ${error.message ?: error::class.java.simpleName}",
                    )
                }
        } else {
            VerificationResult(
                verified = false,
                detail = "Execution did not succeed; clean-state verification was not claimed.",
            )
        }

        audit(
            request = request,
            decision = decision,
            executionResult = execution.resultCode,
            verified = verification.verified,
            detail = "${execution.detail} | ${verification.detail}",
        )

        return BrokerResult.Completed(request, execution, verification)
    }

    private fun validateApproval(
        request: SecurityCommandRequest,
        policy: ActionPolicy,
        approval: HumanApproval?,
    ): String? {
        approval ?: return "Human approval is required."
        if (approval.requestId != request.requestId) return "Approval requestId does not match."
        if (approval.requestFingerprint != request.fingerprint()) return "Approval fingerprint does not match request/arguments."
        if (approval.approvedAtEpochMs > now()) return "Approval timestamp is in the future."
        if (now() - approval.approvedAtEpochMs > approvalTtlMs) return "Approval expired."

        val methodAllowed = when (policy.humanGate) {
            HumanGate.NONE -> true
            HumanGate.EXPLICIT_CONFIRMATION -> approval.method == ApprovalMethod.EXPLICIT_UI || approval.method == ApprovalMethod.BIOMETRIC_AND_UI
            HumanGate.BIOMETRIC_AND_EXPLICIT -> approval.method == ApprovalMethod.BIOMETRIC_AND_UI
        }
        if (!methodAllowed) return "Approval method is insufficient for ${policy.humanGate}."
        if (!replayGuard.consumeOnce(approval.approvalId)) return "Approval was already consumed."
        return null
    }

    private fun deniedMissingImplementation(
        request: SecurityCommandRequest,
        policyDecision: PolicyDecision,
        reason: String,
    ): BrokerResult.Denied {
        val denied = PolicyDecision(
            type = PolicyDecisionType.DENY_POLICY,
            policy = policyDecision.policy,
            reason = reason,
        )
        audit(request, denied, null, null, reason)
        return BrokerResult.Denied(request, denied)
    }

    private fun audit(
        request: SecurityCommandRequest,
        decision: PolicyDecision,
        executionResult: String?,
        verified: Boolean?,
        detail: String,
    ) {
        auditSink.append(
            CommandAuditEvent(
                timestampEpochMs = now(),
                requestId = request.requestId,
                source = request.source,
                action = request.action,
                policyDecision = decision.type,
                humanGate = decision.policy.humanGate,
                executionResult = executionResult,
                verified = verified,
                detail = detail,
            ),
        )
    }
}
