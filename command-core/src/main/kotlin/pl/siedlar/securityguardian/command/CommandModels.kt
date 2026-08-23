package pl.siedlar.securityguardian.command

import java.security.MessageDigest

enum class PrivilegeLevel {
    STANDARD,
    ADVANCED,
    DEVICE_OWNER,
    ROOT_ENTERPRISE,
}

enum class CommandSource {
    USER,
    AI,
    SYSTEM,
}

enum class CommandRisk {
    READ_ONLY,
    REVERSIBLE,
    DESTRUCTIVE,
    IRREVERSIBLE,
}

enum class HumanGate {
    NONE,
    EXPLICIT_CONFIRMATION,
    BIOMETRIC_AND_EXPLICIT,
}

enum class DeviceCapability {
    APP_INVENTORY,
    PRIVACY_INSPECTION,
    URL_SCAN,
    FILE_SCAN,
    QUARANTINE_COPY,
    DOCUMENT_DELETE,
    DNS_GUARD,
    APP_NETWORK_BLOCK,
    APP_UNINSTALL_REQUEST,
    DEVICE_OWNER_POLICY,
    FACTORY_RESET,
}

enum class SecurityAction {
    RUN_FULL_SCAN,
    CHECK_PRIVACY,
    CHECK_APP,
    CHECK_URL,
    SCAN_FILE,
    COPY_FILE_TO_VAULT,
    CONTAIN_FILE,
    BLOCK_DOMAIN,
    ALLOW_DOMAIN_TEMPORARILY,
    BLOCK_APP_NETWORK,
    REQUEST_APP_UNINSTALL,
    RESTORE_FILE,
    DELETE_FILE,
    FACTORY_RESET,
}

data class SecurityCommandRequest(
    val requestId: String,
    val action: SecurityAction,
    val arguments: Map<String, String> = emptyMap(),
    val source: CommandSource,
) {
    init {
        require(requestId.isNotBlank())
        require(arguments.size <= MAX_ARGUMENTS)
        arguments.forEach { (key, value) ->
            require(key.isNotBlank() && key.length <= MAX_ARGUMENT_KEY_CHARS)
            require(value.length <= MAX_ARGUMENT_VALUE_CHARS)
        }
    }

    fun fingerprint(): String {
        val canonical = buildString {
            append(requestId).append('\n')
            append(action.name).append('\n')
            arguments.toSortedMap().forEach { (key, value) ->
                append(key).append('=').append(value).append('\n')
            }
        }
        return MessageDigest.getInstance("SHA-256")
            .digest(canonical.toByteArray(Charsets.UTF_8))
            .joinToString("") { byte -> "%02x".format(byte) }
    }

    private companion object {
        const val MAX_ARGUMENTS = 32
        const val MAX_ARGUMENT_KEY_CHARS = 64
        const val MAX_ARGUMENT_VALUE_CHARS = 4_096
    }
}

data class CapabilitySnapshot(
    val privilegeLevel: PrivilegeLevel,
    val available: Set<DeviceCapability>,
)

data class ActionPolicy(
    val action: SecurityAction,
    val risk: CommandRisk,
    val minimumPrivilege: PrivilegeLevel,
    val requiredCapabilities: Set<DeviceCapability>,
    val humanGate: HumanGate,
)

enum class ApprovalMethod {
    EXPLICIT_UI,
    BIOMETRIC_AND_UI,
}

data class HumanApproval(
    val approvalId: String,
    val requestId: String,
    val requestFingerprint: String,
    val approvedAtEpochMs: Long,
    val method: ApprovalMethod,
) {
    init {
        require(approvalId.isNotBlank())
        require(requestId.isNotBlank())
        require(requestFingerprint.length == 64)
    }
}

enum class PolicyDecisionType {
    ALLOW,
    REQUIRE_HUMAN_GATE,
    DENY_CAPABILITY,
    DENY_PRIVILEGE,
    DENY_POLICY,
}

data class PolicyDecision(
    val type: PolicyDecisionType,
    val policy: ActionPolicy,
    val reason: String,
)

data class ExecutionResult(
    val success: Boolean,
    val resultCode: String,
    val detail: String,
    val verificationData: Map<String, String> = emptyMap(),
)

data class VerificationResult(
    val verified: Boolean,
    val detail: String,
)

data class CommandAuditEvent(
    val timestampEpochMs: Long,
    val requestId: String,
    val source: CommandSource,
    val action: SecurityAction,
    val policyDecision: PolicyDecisionType,
    val humanGate: HumanGate,
    val executionResult: String?,
    val verified: Boolean?,
    val detail: String,
)
