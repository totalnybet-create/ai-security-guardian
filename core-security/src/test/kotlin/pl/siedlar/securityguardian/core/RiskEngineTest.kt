package pl.siedlar.securityguardian.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RiskEngineTest {
    private val engine = RiskEngine()

    @Test
    fun trustedOrdinaryAppIsNotInventedAsThreat() {
        val app = snapshot(
            installer = "com.android.vending",
        )

        val result = engine.assess(app)

        assertEquals(0, result.riskScore)
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertTrue(result.evidence.isEmpty())
    }

    @Test
    fun correlatedControlCapabilitiesBecomeCritical() {
        val app = snapshot(
            installer = null,
            requested = setOf(
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.REQUEST_INSTALL_PACKAGES",
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
            ),
            granted = setOf(
                "android.permission.RECORD_AUDIO",
                "android.permission.CAMERA",
            ),
            accessibilityEnabled = true,
            declaresAccessibility = true,
        )

        val result = engine.assess(app)

        assertEquals(RiskLevel.CRITICAL, result.riskLevel)
        assertTrue(result.evidence.any { it.id == "corr_accessibility_overlay" })
        assertTrue(result.evidence.any { it.id == "corr_accessibility_installer" })
    }

    @Test
    fun fullScanPublishesRealHighRiskAlertAndAudit() {
        val risky = snapshot(
            packageName = "test.risky",
            installer = null,
            requested = setOf("android.permission.SYSTEM_ALERT_WINDOW"),
            accessibilityEnabled = true,
            declaresAccessibility = true,
        )
        val audits = mutableListOf<AuditEvent>()
        val alerts = mutableListOf<AppAssessment>()

        val service = FullScanService(
            inventory = object : AppInventorySource {
                override fun collect(): List<AppSnapshot> = listOf(risky)
            },
            riskEngine = engine,
            auditSink = object : AuditSink {
                override fun append(event: AuditEvent) {
                    audits += event
                }
            },
            alertSink = object : SecurityAlertSink {
                override fun publish(assessment: AppAssessment) {
                    alerts += assessment
                }
            },
            now = { 1_000L },
        )

        val report = service.run()

        assertTrue(report.highOrCriticalCount >= 1)
        assertTrue(alerts.isNotEmpty())
        assertTrue(audits.any { it.event == "APP_RISK_DETECTED" })
        assertTrue(audits.any { it.event == "FULL_APP_SCAN_COMPLETED" })
    }

    private fun snapshot(
        packageName: String = "test.app",
        installer: String? = "com.android.vending",
        requested: Set<String> = emptySet(),
        granted: Set<String> = emptySet(),
        accessibilityEnabled: Boolean = false,
        declaresAccessibility: Boolean = false,
    ) = AppSnapshot(
        packageName = packageName,
        label = packageName,
        versionName = "1.0",
        installerPackage = installer,
        firstInstallTimeEpochMs = 1L,
        lastUpdateTimeEpochMs = 1L,
        certificateSha256 = "certificate",
        apkSha256 = "apk",
        requestedPermissions = requested,
        grantedPermissions = granted,
        isSystemApp = false,
        accessibilityEnabled = accessibilityEnabled,
        deviceAdminActive = false,
        declaresAccessibilityService = declaresAccessibility,
        declaresNotificationListener = false,
        declaresVpnService = false,
    )
}
