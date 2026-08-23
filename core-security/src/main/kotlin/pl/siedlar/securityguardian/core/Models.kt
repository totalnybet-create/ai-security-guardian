package pl.siedlar.securityguardian.core

enum class RiskLevel {
    SAFE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL;

    companion object {
        fun fromScore(score: Int): RiskLevel = when (score.coerceIn(0, 100)) {
            in 0..9 -> SAFE
            in 10..29 -> LOW
            in 30..49 -> MEDIUM
            in 50..74 -> HIGH
            else -> CRITICAL
        }
    }
}

data class AppSnapshot(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val installerPackage: String?,
    val firstInstallTimeEpochMs: Long,
    val lastUpdateTimeEpochMs: Long,
    val certificateSha256: String?,
    val apkSha256: String?,
    val requestedPermissions: Set<String>,
    val grantedPermissions: Set<String>,
    val isSystemApp: Boolean,
    val accessibilityEnabled: Boolean,
    val deviceAdminActive: Boolean,
    val declaresAccessibilityService: Boolean,
    val declaresNotificationListener: Boolean,
    val declaresVpnService: Boolean,
)

data class RiskEvidence(
    val id: String,
    val title: String,
    val detail: String,
    val weight: Int,
)

data class AppAssessment(
    val app: AppSnapshot,
    val riskScore: Int,
    val riskLevel: RiskLevel,
    val confidence: Int,
    val evidence: List<RiskEvidence>,
)

data class DeviceScanReport(
    val startedAtEpochMs: Long,
    val finishedAtEpochMs: Long,
    val assessments: List<AppAssessment>,
    val appSecurityScore: Int,
) {
    val highOrCriticalCount: Int
        get() = assessments.count { it.riskLevel == RiskLevel.HIGH || it.riskLevel == RiskLevel.CRITICAL }

    val criticalCount: Int
        get() = assessments.count { it.riskLevel == RiskLevel.CRITICAL }
}

data class AuditEvent(
    val timestampEpochMs: Long,
    val event: String,
    val source: String,
    val risk: RiskLevel,
    val evidence: List<String>,
    val action: String,
    val result: String,
    val verification: String,
)
