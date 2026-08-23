package pl.siedlar.securityguardian.command

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class SecurityCommandBrokerTest {
    private val audits = mutableListOf<CommandAuditEvent>()
    private var now = 10_000L

    @Test
    fun readOnlyActionExecutesWithoutHumanGate() {
        val broker = brokerFor(SecurityAction.RUN_FULL_SCAN)
        val request = request(SecurityAction.RUN_FULL_SCAN)
        val result = broker.submit(
            request,
            CapabilitySnapshot(PrivilegeLevel.STANDARD, setOf(DeviceCapability.APP_INVENTORY)),
        )
        val completed = assertIs<BrokerResult.Completed>(result)
        assertTrue(completed.execution.success)
        assertTrue(completed.verification.verified)
    }

    @Test
    fun missingCapabilityDeniesBeforeExecutor() {
        var executed = false
        val broker = brokerFor(SecurityAction.BLOCK_DOMAIN) { executed = true }
        val result = broker.submit(
            request(SecurityAction.BLOCK_DOMAIN),
            CapabilitySnapshot(PrivilegeLevel.STANDARD, emptySet()),
        )
        assertIs<BrokerResult.Denied>(result)
        assertFalse(executed)
    }

    @Test
    fun destructiveActionRequiresExplicitApproval() {
        val request = request(SecurityAction.DELETE_FILE, mapOf("uri" to "content://file/1"))
        val broker = brokerFor(SecurityAction.DELETE_FILE)
        val capabilities = CapabilitySnapshot(PrivilegeLevel.STANDARD, setOf(DeviceCapability.DOCUMENT_DELETE))
        assertIs<BrokerResult.AwaitingHumanGate>(broker.submit(request, capabilities))

        val approval = approval(request, ApprovalMethod.EXPLICIT_UI)
        assertIs<BrokerResult.Completed>(broker.submit(request, capabilities, approval))
    }

    @Test
    fun approvalCannotAuthorizeChangedArguments() {
        val approvedRequest = request(SecurityAction.DELETE_FILE, mapOf("uri" to "content://file/1"))
        val changedRequest = approvedRequest.copy(arguments = mapOf("uri" to "content://file/2"))
        val broker = brokerFor(SecurityAction.DELETE_FILE)
        val capabilities = CapabilitySnapshot(PrivilegeLevel.STANDARD, setOf(DeviceCapability.DOCUMENT_DELETE))

        val result = broker.submit(
            changedRequest,
            capabilities,
            approval(approvedRequest, ApprovalMethod.EXPLICIT_UI),
        )
        assertIs<BrokerResult.AwaitingHumanGate>(result)
    }

    @Test
    fun approvalIsOneTime() {
        val request = request(SecurityAction.DELETE_FILE, mapOf("uri" to "content://file/1"))
        val broker = brokerFor(SecurityAction.DELETE_FILE)
        val capabilities = CapabilitySnapshot(PrivilegeLevel.STANDARD, setOf(DeviceCapability.DOCUMENT_DELETE))
        val approval = approval(request, ApprovalMethod.EXPLICIT_UI)

        assertIs<BrokerResult.Completed>(broker.submit(request, capabilities, approval))
        assertIs<BrokerResult.AwaitingHumanGate>(broker.submit(request, capabilities, approval))
    }

    @Test
    fun factoryResetRequiresDeviceOwnerCapabilitiesAndBiometricApproval() {
        val request = request(SecurityAction.FACTORY_RESET)
        val broker = brokerFor(SecurityAction.FACTORY_RESET)
        val standard = CapabilitySnapshot(PrivilegeLevel.STANDARD, emptySet())
        assertIs<BrokerResult.Denied>(broker.submit(request, standard))

        val managed = CapabilitySnapshot(
            PrivilegeLevel.DEVICE_OWNER,
            setOf(DeviceCapability.DEVICE_OWNER_POLICY, DeviceCapability.FACTORY_RESET),
        )
        assertIs<BrokerResult.AwaitingHumanGate>(
            broker.submit(request, managed, approval(request, ApprovalMethod.EXPLICIT_UI)),
        )
        assertIs<BrokerResult.Completed>(
            broker.submit(request, managed, approval(request, ApprovalMethod.BIOMETRIC_AND_UI, "bio-2")),
        )
    }

    @Test
    fun expiredApprovalIsRejected() {
        val request = request(SecurityAction.DELETE_FILE)
        val broker = brokerFor(SecurityAction.DELETE_FILE)
        val capabilities = CapabilitySnapshot(PrivilegeLevel.STANDARD, setOf(DeviceCapability.DOCUMENT_DELETE))
        val approval = approval(request, ApprovalMethod.EXPLICIT_UI).copy(approvedAtEpochMs = now - 121_000L)
        assertIs<BrokerResult.AwaitingHumanGate>(broker.submit(request, capabilities, approval))
    }

    private fun brokerFor(
        action: SecurityAction,
        onExecute: () -> Unit = {},
    ): SecurityCommandBroker = SecurityCommandBroker(
        executors = listOf(
            object : SecurityCommandExecutor {
                override val action = action
                override fun execute(request: SecurityCommandRequest): ExecutionResult {
                    onExecute()
                    return ExecutionResult(true, "OK", "executed", mapOf("proof" to "yes"))
                }
            },
        ),
        verifiers = listOf(
            object : SecurityCommandVerifier {
                override val action = action
                override fun verify(request: SecurityCommandRequest, execution: ExecutionResult) =
                    VerificationResult(execution.verificationData["proof"] == "yes", "verified")
            },
        ),
        auditSink = CommandAuditSink(audits::add),
        approvalTtlMs = 120_000L,
        now = { now },
    )

    private fun request(
        action: SecurityAction,
        arguments: Map<String, String> = emptyMap(),
    ) = SecurityCommandRequest(
        requestId = "req-${action.name}-${arguments.hashCode()}",
        action = action,
        arguments = arguments,
        source = CommandSource.AI,
    )

    private fun approval(
        request: SecurityCommandRequest,
        method: ApprovalMethod,
        id: String = "approval-${request.requestId}",
    ) = HumanApproval(
        approvalId = id,
        requestId = request.requestId,
        requestFingerprint = request.fingerprint(),
        approvedAtEpochMs = now,
        method = method,
    )
}
