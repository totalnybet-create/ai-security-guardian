package pl.siedlar.securityguardian.core

class FullScanService(
    private val inventory: AppInventorySource,
    private val riskEngine: RiskEngine,
    private val auditSink: AuditSink,
    private val alertSink: SecurityAlertSink,
    private val now: () -> Long = { System.currentTimeMillis() },
) {
    fun run(): DeviceScanReport {
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
                        event = "APP_RISK_DETECTED",
                        source = assessment.app.packageName,
                        risk = assessment.riskLevel,
                        evidence = assessment.evidence.map { it.id },
                        action = "ALERT",
                        result = "PUBLISHED",
                        verification = "Assessment persisted in scan report",
                    ),
                )
                alertSink.publish(assessment)
            }

        val appSecurityScore = 100 - (assessments.maxOfOrNull { it.riskScore } ?: 0)
        val report = DeviceScanReport(
            startedAtEpochMs = started,
            finishedAtEpochMs = now(),
            assessments = assessments,
            appSecurityScore = appSecurityScore.coerceIn(0, 100),
        )

        auditSink.append(
            AuditEvent(
                timestampEpochMs = report.finishedAtEpochMs,
                event = "FULL_APP_SCAN_COMPLETED",
                source = "security-core",
                risk = assessments.firstOrNull()?.riskLevel ?: RiskLevel.SAFE,
                evidence = listOf(
                    "apps=${assessments.size}",
                    "high_or_critical=${report.highOrCriticalCount}",
                    "app_security_score=${report.appSecurityScore}",
                ),
                action = "SCAN",
                result = "COMPLETED",
                verification = "Report contains one assessment per collected package",
            ),
        )

        return report
    }
}
