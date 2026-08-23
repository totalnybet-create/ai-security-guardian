package pl.siedlar.securityguardian.privacy

import pl.siedlar.securityguardian.core.AuditEvent
import pl.siedlar.securityguardian.core.AuditSink
import pl.siedlar.securityguardian.core.RiskLevel

data class PrivacyScanReport(
    val startedAtEpochMs: Long,
    val finishedAtEpochMs: Long,
    val assessments: List<PrivacyAssessment>,
    val privacySecurityScore: Int,
) {
    val highOrCriticalCount: Int
        get() = assessments.count { it.riskLevel == RiskLevel.HIGH || it.riskLevel == RiskLevel.CRITICAL }
}

class PrivacyScanService(
    private val inventory: PrivacyInventorySource,
    private val riskEngine: PrivacyRiskEngine,
    private val auditSink: AuditSink,
    private val alertSink: PrivacyAlertSink,
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    fun run(): PrivacyScanReport {
        val started = now()
        val assessments = inventory.collect()
            .map(riskEngine::assess)
            .sortedByDescending { it.riskScore }

        assessments
            .filter { it.riskLevel == RiskLevel.HIGH || it.riskLevel == RiskLevel.CRITICAL }
            .forEach { assessment ->
                auditSink.append(
                    AuditEvent(
                        timestampEpochMs = now(),
                        event = "PRIVACY_RISK_DETECTED",
                        source = assessment.snapshot.packageName,
                        risk = assessment.riskLevel,
                        evidence = assessment.evidence.map { it.id },
                        action = "ALERT",
                        result = "PUBLISHED",
                        verification = "Privacy assessment persisted in scan report",
                    ),
                )
                alertSink.publish(assessment)
            }

        val privacySecurityScore = 100 - (assessments.maxOfOrNull { it.riskScore } ?: 0)
        val report = PrivacyScanReport(
            startedAtEpochMs = started,
            finishedAtEpochMs = now(),
            assessments = assessments,
            privacySecurityScore = privacySecurityScore.coerceIn(0, 100),
        )

        auditSink.append(
            AuditEvent(
                timestampEpochMs = report.finishedAtEpochMs,
                event = "PRIVACY_SCAN_COMPLETED",
                source = "privacy-guard",
                risk = assessments.firstOrNull()?.riskLevel ?: RiskLevel.SAFE,
                evidence = listOf(
                    "apps=${assessments.size}",
                    "high_or_critical=${report.highOrCriticalCount}",
                    "privacy_security_score=${report.privacySecurityScore}",
                ),
                action = "SCAN",
                result = "COMPLETED",
                verification = "Report contains one privacy assessment per collected package",
            ),
        )

        return report
    }
}
