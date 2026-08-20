package pl.siedlar.securityguardian.command

class SecurityPolicyCatalog(
    policies: List<ActionPolicy> = defaultPolicies(),
) {
    private val byAction = policies.associateBy(ActionPolicy::action)

    init {
        require(byAction.size == SecurityAction.entries.size) {
            "Every SecurityAction must have exactly one policy"
        }
    }

    fun policyFor(action: SecurityAction): ActionPolicy =
        requireNotNull(byAction[action]) { "Missing policy for $action" }

    companion object {
        fun defaultPolicies(): List<ActionPolicy> = listOf(
            ActionPolicy(SecurityAction.RUN_FULL_SCAN, CommandRisk.READ_ONLY, PrivilegeLevel.STANDARD, setOf(DeviceCapability.APP_INVENTORY), HumanGate.NONE),
            ActionPolicy(SecurityAction.CHECK_PRIVACY, CommandRisk.READ_ONLY, PrivilegeLevel.STANDARD, setOf(DeviceCapability.PRIVACY_INSPECTION), HumanGate.NONE),
            ActionPolicy(SecurityAction.CHECK_APP, CommandRisk.READ_ONLY, PrivilegeLevel.STANDARD, setOf(DeviceCapability.APP_INVENTORY), HumanGate.NONE),
            ActionPolicy(SecurityAction.CHECK_URL, CommandRisk.READ_ONLY, PrivilegeLevel.STANDARD, setOf(DeviceCapability.URL_SCAN), HumanGate.NONE),
            ActionPolicy(SecurityAction.SCAN_FILE, CommandRisk.READ_ONLY, PrivilegeLevel.STANDARD, setOf(DeviceCapability.FILE_SCAN), HumanGate.NONE),
            ActionPolicy(SecurityAction.COPY_FILE_TO_VAULT, CommandRisk.REVERSIBLE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.QUARANTINE_COPY), HumanGate.NONE),
            ActionPolicy(SecurityAction.CONTAIN_FILE, CommandRisk.DESTRUCTIVE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.QUARANTINE_COPY, DeviceCapability.DOCUMENT_DELETE), HumanGate.EXPLICIT_CONFIRMATION),
            ActionPolicy(SecurityAction.BLOCK_DOMAIN, CommandRisk.REVERSIBLE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.DNS_GUARD), HumanGate.NONE),
            ActionPolicy(SecurityAction.ALLOW_DOMAIN_TEMPORARILY, CommandRisk.REVERSIBLE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.DNS_GUARD), HumanGate.NONE),
            ActionPolicy(SecurityAction.BLOCK_APP_NETWORK, CommandRisk.REVERSIBLE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.APP_NETWORK_BLOCK), HumanGate.NONE),
            ActionPolicy(SecurityAction.REQUEST_APP_UNINSTALL, CommandRisk.DESTRUCTIVE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.APP_UNINSTALL_REQUEST), HumanGate.EXPLICIT_CONFIRMATION),
            ActionPolicy(SecurityAction.RESTORE_FILE, CommandRisk.REVERSIBLE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.QUARANTINE_COPY), HumanGate.EXPLICIT_CONFIRMATION),
            ActionPolicy(SecurityAction.DELETE_FILE, CommandRisk.DESTRUCTIVE, PrivilegeLevel.STANDARD, setOf(DeviceCapability.DOCUMENT_DELETE), HumanGate.EXPLICIT_CONFIRMATION),
            ActionPolicy(SecurityAction.FACTORY_RESET, CommandRisk.IRREVERSIBLE, PrivilegeLevel.DEVICE_OWNER, setOf(DeviceCapability.DEVICE_OWNER_POLICY, DeviceCapability.FACTORY_RESET), HumanGate.BIOMETRIC_AND_EXPLICIT),
        )
    }
}

class SecurityPolicyEngine(
    private val catalog: SecurityPolicyCatalog = SecurityPolicyCatalog(),
) {
    fun evaluate(
        request: SecurityCommandRequest,
        capabilities: CapabilitySnapshot,
    ): PolicyDecision {
        val policy = catalog.policyFor(request.action)

        if (capabilities.privilegeLevel.ordinal < policy.minimumPrivilege.ordinal) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY_PRIVILEGE,
                policy = policy,
                reason = "Action requires ${policy.minimumPrivilege}, current level is ${capabilities.privilegeLevel}.",
            )
        }

        val missing = policy.requiredCapabilities - capabilities.available
        if (missing.isNotEmpty()) {
            return PolicyDecision(
                type = PolicyDecisionType.DENY_CAPABILITY,
                policy = policy,
                reason = "Missing capabilities: ${missing.sortedBy { it.name }.joinToString()}.",
            )
        }

        if (policy.humanGate != HumanGate.NONE) {
            return PolicyDecision(
                type = PolicyDecisionType.REQUIRE_HUMAN_GATE,
                policy = policy,
                reason = "Action requires ${policy.humanGate}.",
            )
        }

        return PolicyDecision(
            type = PolicyDecisionType.ALLOW,
            policy = policy,
            reason = "Policy and capability checks passed.",
        )
    }
}
