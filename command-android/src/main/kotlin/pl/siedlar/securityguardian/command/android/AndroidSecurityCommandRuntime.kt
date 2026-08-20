package pl.siedlar.securityguardian.command.android

import android.content.Context
import android.os.Build
import pl.siedlar.securityguardian.audit.JsonlAuditLogger
import pl.siedlar.securityguardian.command.BrokerResult
import pl.siedlar.securityguardian.command.CapabilitySnapshot
import pl.siedlar.securityguardian.command.CommandAuditEvent
import pl.siedlar.securityguardian.command.CommandAuditSink
import pl.siedlar.securityguardian.command.DeviceCapability
import pl.siedlar.securityguardian.command.ExecutionResult
import pl.siedlar.securityguardian.command.PolicyDecisionType
import pl.siedlar.securityguardian.command.PrivilegeLevel
import pl.siedlar.securityguardian.command.SecurityAction
import pl.siedlar.securityguardian.command.SecurityCommandBroker
import pl.siedlar.securityguardian.command.SecurityCommandExecutor
import pl.siedlar.securityguardian.command.SecurityCommandRequest
import pl.siedlar.securityguardian.command.SecurityCommandVerifier
import pl.siedlar.securityguardian.command.VerificationResult
import pl.siedlar.securityguardian.core.AppInventorySource
import pl.siedlar.securityguardian.core.AppSnapshot
import pl.siedlar.securityguardian.core.AuditEvent
import pl.siedlar.securityguardian.core.FullScanService
import pl.siedlar.securityguardian.core.RiskEngine
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.inspector.AndroidAppInspector
import pl.siedlar.securityguardian.inspector.AndroidPrivacyInspector
import pl.siedlar.securityguardian.network.NetworkAction
import pl.siedlar.securityguardian.network.android.AndroidNetworkRuleStore
import pl.siedlar.securityguardian.network.android.DnsGuardController
import pl.siedlar.securityguardian.network.android.DnsGuardState
import pl.siedlar.securityguardian.notifications.AndroidPrivacyAlertSink
import pl.siedlar.securityguardian.notifications.AndroidSecurityAlertSink
import pl.siedlar.securityguardian.privacy.PrivacyRiskEngine
import pl.siedlar.securityguardian.privacy.PrivacyScanService
import pl.siedlar.securityguardian.url.UrlRiskEngine

class AndroidSecurityCommandRuntime(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val auditLogger = JsonlAuditLogger(appContext)
    private val networkRules = AndroidNetworkRuleStore(appContext)
    private val dnsController = DnsGuardController(appContext)

    val supportedActions: Set<SecurityAction> = setOf(
        SecurityAction.RUN_FULL_SCAN,
        SecurityAction.CHECK_PRIVACY,
        SecurityAction.CHECK_APP,
        SecurityAction.CHECK_URL,
        SecurityAction.BLOCK_DOMAIN,
        SecurityAction.ALLOW_DOMAIN_TEMPORARILY,
    )

    val capabilities: CapabilitySnapshot
        get() = CapabilitySnapshot(
            privilegeLevel = PrivilegeLevel.STANDARD,
            available = buildSet {
                add(DeviceCapability.APP_INVENTORY)
                add(DeviceCapability.PRIVACY_INSPECTION)
                add(DeviceCapability.URL_SCAN)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    add(DeviceCapability.DNS_GUARD)
                }
            },
        )

    private val broker = SecurityCommandBroker(
        executors = supportedActions.map(::executorFor),
        verifiers = supportedActions.map(::verifierFor),
        auditSink = AndroidCommandAuditSink(auditLogger),
    )

    fun submit(request: SecurityCommandRequest): BrokerResult = broker.submit(
        request = request,
        capabilities = capabilities,
    )

    private fun executorFor(action: SecurityAction): SecurityCommandExecutor = object : SecurityCommandExecutor {
        override val action: SecurityAction = action

        override fun execute(request: SecurityCommandRequest): ExecutionResult = when (action) {
            SecurityAction.RUN_FULL_SCAN -> executeFullScan()
            SecurityAction.CHECK_PRIVACY -> executePrivacyScan()
            SecurityAction.CHECK_APP -> executeCheckApp(request)
            SecurityAction.CHECK_URL -> executeCheckUrl(request)
            SecurityAction.BLOCK_DOMAIN -> executeBlockDomain(request)
            SecurityAction.ALLOW_DOMAIN_TEMPORARILY -> executeTemporaryAllow(request)
            else -> ExecutionResult(false, "UNSUPPORTED_ACTION", "No Android executor for $action")
        }
    }

    private fun verifierFor(action: SecurityAction): SecurityCommandVerifier = object : SecurityCommandVerifier {
        override val action: SecurityAction = action

        override fun verify(
            request: SecurityCommandRequest,
            execution: ExecutionResult,
        ): VerificationResult = when (action) {
            SecurityAction.RUN_FULL_SCAN -> verifyScores(execution, requirePrivacy = true)
            SecurityAction.CHECK_PRIVACY -> verifyPrivacy(execution)
            SecurityAction.CHECK_APP -> verifyApp(request, execution)
            SecurityAction.CHECK_URL -> verifyUrl(execution)
            SecurityAction.BLOCK_DOMAIN -> verifyBlockedDomain(execution)
            SecurityAction.ALLOW_DOMAIN_TEMPORARILY -> verifyTemporaryAllow(execution)
            else -> VerificationResult(false, "No verifier for $action")
        }
    }

    private fun executeFullScan(): ExecutionResult {
        val rawInventory = AndroidAppInspector(appContext)
        val sharedInventory = cachedInventory(rawInventory)
        val appReport = FullScanService(
            inventory = sharedInventory,
            riskEngine = RiskEngine(),
            auditSink = auditLogger,
            alertSink = AndroidSecurityAlertSink(appContext),
        ).run()
        val privacyReport = PrivacyScanService(
            inventory = AndroidPrivacyInspector(appContext, sharedInventory),
            riskEngine = PrivacyRiskEngine(),
            auditSink = auditLogger,
            alertSink = AndroidPrivacyAlertSink(appContext),
        ).run()

        return ExecutionResult(
            success = true,
            resultCode = "FULL_SCAN_COMPLETED",
            detail = "Skan aplikacji i prywatności zakończony w aktualnie wdrożonym zakresie.",
            verificationData = mapOf(
                "appCount" to appReport.assessments.size.toString(),
                "appScore" to appReport.appSecurityScore.toString(),
                "privacyCount" to privacyReport.assessments.size.toString(),
                "privacyScore" to privacyReport.privacySecurityScore.toString(),
                "highOrCritical" to (appReport.highOrCriticalCount + privacyReport.highOrCriticalCount).toString(),
                "scope" to "P0_APP+P1_PRIVACY",
            ),
        )
    }

    private fun executePrivacyScan(): ExecutionResult {
        val rawInventory = AndroidAppInspector(appContext)
        val sharedInventory = cachedInventory(rawInventory)
        val report = PrivacyScanService(
            inventory = AndroidPrivacyInspector(appContext, sharedInventory),
            riskEngine = PrivacyRiskEngine(),
            auditSink = auditLogger,
            alertSink = AndroidPrivacyAlertSink(appContext),
        ).run()
        return ExecutionResult(
            success = true,
            resultCode = "PRIVACY_SCAN_COMPLETED",
            detail = "Kontrola prywatności zakończona.",
            verificationData = mapOf(
                "privacyCount" to report.assessments.size.toString(),
                "privacyScore" to report.privacySecurityScore.toString(),
                "highOrCritical" to report.highOrCriticalCount.toString(),
            ),
        )
    }

    private fun executeCheckApp(request: SecurityCommandRequest): ExecutionResult {
        val packageName = request.arguments["packageName"]?.takeIf(String::isNotBlank)
            ?: return ExecutionResult(false, "MISSING_PACKAGE", "Brak packageName")
        val snapshot = AndroidAppInspector(appContext).collectPackage(packageName)
            ?: return ExecutionResult(false, "PACKAGE_NOT_FOUND", "Nie znaleziono pakietu $packageName")
        val assessment = RiskEngine().assess(snapshot)
        return ExecutionResult(
            success = true,
            resultCode = "APP_ASSESSED",
            detail = "${snapshot.label}: ${assessment.riskLevel.name} ${assessment.riskScore}/100",
            verificationData = mapOf(
                "packageName" to snapshot.packageName,
                "riskLevel" to assessment.riskLevel.name,
                "riskScore" to assessment.riskScore.toString(),
                "evidenceCount" to assessment.evidence.size.toString(),
            ),
        )
    }

    private fun executeCheckUrl(request: SecurityCommandRequest): ExecutionResult {
        val url = request.arguments["url"]?.takeIf(String::isNotBlank)
            ?: return ExecutionResult(false, "MISSING_URL", "Brak URL")
        val assessment = UrlRiskEngine().assess(url)
        return ExecutionResult(
            success = true,
            resultCode = "URL_ASSESSED",
            detail = "${assessment.riskLevel.name} ${assessment.riskScore}/100 · ${assessment.normalizedHost ?: "brak hosta"}",
            verificationData = mapOf(
                "host" to assessment.normalizedHost.orEmpty(),
                "scheme" to assessment.scheme.orEmpty(),
                "riskLevel" to assessment.riskLevel.name,
                "riskScore" to assessment.riskScore.toString(),
                "shouldOpenDirectly" to assessment.shouldOpenDirectly.toString(),
            ),
        )
    }

    private fun executeBlockDomain(request: SecurityCommandRequest): ExecutionResult {
        val domain = request.arguments["domain"]?.takeIf(String::isNotBlank)
            ?: return ExecutionResult(false, "MISSING_DOMAIN", "Brak domeny")
        val rule = networkRules.addBlockedDomain(domain)
        val guardRunning = dnsController.status().state == DnsGuardState.RUNNING_DNS_ONLY
        return ExecutionResult(
            success = true,
            resultCode = if (guardRunning) "RULE_STORED_AND_DNS_GUARD_RUNNING" else "RULE_STORED_GUARD_NOT_RUNNING",
            detail = if (guardRunning) {
                "Reguła BLOCK zapisana; DNS Guard raportuje aktywny tryb DNS-only."
            } else {
                "Reguła BLOCK zapisana, ale live DNS enforcement nie jest obecnie aktywny."
            },
            verificationData = mapOf(
                "ruleId" to rule.id,
                "domain" to rule.domainSuffix.orEmpty(),
                "guardRunning" to guardRunning.toString(),
            ),
        )
    }

    private fun executeTemporaryAllow(request: SecurityCommandRequest): ExecutionResult {
        val domain = request.arguments["domain"]?.takeIf(String::isNotBlank)
            ?: return ExecutionResult(false, "MISSING_DOMAIN", "Brak domeny")
        val duration = request.arguments["durationMinutes"]?.toIntOrNull() ?: 10

        val normalizedBlocked = networkRules.listUserRules().firstOrNull { it.domainSuffix == domain }
        if (normalizedBlocked != null) {
            return ExecutionResult(
                false,
                "PERMANENT_BLOCK_PRESENT",
                "Domena ma ręczną regułę BLOCK; tymczasowe ALLOW nie może jej po cichu osłabić.",
            )
        }

        val rule = networkRules.allowDomainTemporarily(domain, duration)
        return ExecutionResult(
            success = true,
            resultCode = "TEMPORARY_ALLOW_STORED",
            detail = "Tymczasowe zezwolenie zapisane na $duration min.",
            verificationData = mapOf(
                "ruleId" to rule.id,
                "domain" to rule.domainSuffix.orEmpty(),
                "expiresAt" to rule.expiresAtEpochMs.toString(),
            ),
        )
    }

    private fun verifyScores(execution: ExecutionResult, requirePrivacy: Boolean): VerificationResult {
        val appScore = execution.verificationData["appScore"]?.toIntOrNull()
        val privacyScore = execution.verificationData["privacyScore"]?.toIntOrNull()
        val valid = appScore in 0..100 && (!requirePrivacy || privacyScore in 0..100)
        return VerificationResult(
            valid,
            if (valid) "Zweryfikowano raport i zakres skanu." else "Raport nie zawiera poprawnych wyników skanu.",
        )
    }

    private fun verifyPrivacy(execution: ExecutionResult): VerificationResult {
        val score = execution.verificationData["privacyScore"]?.toIntOrNull()
        val count = execution.verificationData["privacyCount"]?.toIntOrNull()
        val valid = score in 0..100 && count != null && count >= 0
        return VerificationResult(valid, if (valid) "Raport prywatności zweryfikowany." else "Brak poprawnego raportu prywatności.")
    }

    private fun verifyApp(request: SecurityCommandRequest, execution: ExecutionResult): VerificationResult {
        val expected = request.arguments["packageName"]
        val actual = execution.verificationData["packageName"]
        val score = execution.verificationData["riskScore"]?.toIntOrNull()
        val valid = expected != null && expected == actual && score in 0..100
        return VerificationResult(valid, if (valid) "Ocena dotyczy żądanego pakietu." else "Nie potwierdzono oceny żądanego pakietu.")
    }

    private fun verifyUrl(execution: ExecutionResult): VerificationResult {
        val score = execution.verificationData["riskScore"]?.toIntOrNull()
        val level = execution.verificationData["riskLevel"]
        val valid = score in 0..100 && !level.isNullOrBlank()
        return VerificationResult(valid, if (valid) "Lokalna ocena URL zawiera wynik i verdict." else "Nie potwierdzono kompletnej oceny URL.")
    }

    private fun verifyBlockedDomain(execution: ExecutionResult): VerificationResult {
        val ruleId = execution.verificationData["ruleId"] ?: return VerificationResult(false, "Brak ruleId")
        val stored = networkRules.listUserRules().any { it.id == ruleId && it.action == NetworkAction.BLOCK }
        val running = execution.verificationData["guardRunning"] == "true"
        return VerificationResult(
            stored,
            when {
                !stored -> "Reguła BLOCK nie została odnaleziona po zapisie."
                running -> "Reguła BLOCK jest zapisana, a DNS Guard raportuje live DNS-only."
                else -> "Reguła BLOCK jest zapisana; live DNS enforcement nie jest obecnie aktywny."
            },
        )
    }

    private fun verifyTemporaryAllow(execution: ExecutionResult): VerificationResult {
        val ruleId = execution.verificationData["ruleId"] ?: return VerificationResult(false, "Brak ruleId")
        val rule = networkRules.list().firstOrNull { it.id == ruleId }
        val valid = rule?.action == NetworkAction.TEMPORARY_ALLOW &&
            (rule.expiresAtEpochMs ?: 0L) > System.currentTimeMillis()
        return VerificationResult(valid, if (valid) "Tymczasowe ALLOW jest aktywne i ma przyszłe expiry." else "Nie potwierdzono aktywnego tymczasowego ALLOW.")
    }

    private fun cachedInventory(source: AppInventorySource): AppInventorySource = object : AppInventorySource {
        private var cache: List<AppSnapshot>? = null
        override fun collect(): List<AppSnapshot> {
            cache?.let { return it }
            return source.collect().also { cache = it }
        }
    }
}

private class AndroidCommandAuditSink(
    private val logger: JsonlAuditLogger,
) : CommandAuditSink {
    override fun append(event: CommandAuditEvent) {
        val risk = when {
            event.verified == false -> RiskLevel.MEDIUM
            event.policyDecision == PolicyDecisionType.DENY_CAPABILITY ||
                event.policyDecision == PolicyDecisionType.DENY_PRIVILEGE ||
                event.policyDecision == PolicyDecisionType.DENY_POLICY -> RiskLevel.LOW
            else -> RiskLevel.SAFE
        }
        logger.append(
            AuditEvent(
                timestampEpochMs = event.timestampEpochMs,
                event = "SECURITY_COMMAND_${event.action.name}",
                source = event.source.name,
                risk = risk,
                evidence = listOf(
                    "request=${event.requestId}",
                    "policy=${event.policyDecision}",
                    "gate=${event.humanGate}",
                ),
                action = event.action.name,
                result = event.executionResult ?: event.policyDecision.name,
                verification = event.detail,
            ),
        )
    }
}
