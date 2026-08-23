package pl.siedlar.securityguardian.installguard

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import pl.siedlar.securityguardian.audit.JsonlAuditLogger
import pl.siedlar.securityguardian.core.AppAssessment
import pl.siedlar.securityguardian.core.AppSnapshot
import pl.siedlar.securityguardian.core.AuditEvent
import pl.siedlar.securityguardian.core.RiskEngine
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.inspector.AndroidAppInspector
import pl.siedlar.securityguardian.notifications.AndroidSecurityAlertSink
import java.util.concurrent.atomic.AtomicBoolean

enum class InstallObservationSource {
    PROCESS_BROADCAST,
    PROCESS_START_RECONCILIATION,
}

data class InstallGuardFinding(
    val packageName: String,
    val source: InstallObservationSource,
    val assessment: AppAssessment,
)

class AndroidInstallGuard(
    context: Context,
    private val onFinding: (InstallGuardFinding) -> Unit = {},
) {
    private val appContext = context.applicationContext
    private val packageManager = appContext.packageManager
    private val inspector = AndroidAppInspector(appContext)
    private val riskEngine = RiskEngine()
    private val audit = JsonlAuditLogger(appContext)
    private val alert = AndroidSecurityAlertSink(appContext)
    private val baseline = InstallBaselineStore(appContext)
    private val started = AtomicBoolean(false)

    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val action = intent.action ?: return
            if (action != Intent.ACTION_PACKAGE_ADDED && action != Intent.ACTION_PACKAGE_REPLACED) return
            if (action == Intent.ACTION_PACKAGE_ADDED && intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) return

            val packageName = intent.data?.schemeSpecificPart ?: return
            if (packageName == appContext.packageName) return

            val pending = goAsync()
            Thread {
                try {
                    inspectOne(packageName, InstallObservationSource.PROCESS_BROADCAST)
                    refreshBaselineFor(packageName)
                } finally {
                    pending.finish()
                }
            }.start()
        }
    }

    fun start() {
        if (!started.compareAndSet(false, true)) return

        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_PACKAGE_ADDED)
            addAction(Intent.ACTION_PACKAGE_REPLACED)
            addDataScheme("package")
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            appContext.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            appContext.registerReceiver(receiver, filter)
        }

        Thread {
            runCatching { reconcileAtProcessStart() }
                .onFailure { error ->
                    audit.append(
                        AuditEvent(
                            timestampEpochMs = System.currentTimeMillis(),
                            event = "INSTALL_GUARD_RECONCILIATION_FAILED",
                            source = "install-guard",
                            risk = RiskLevel.LOW,
                            evidence = listOf(error.message ?: error::class.java.simpleName),
                            action = "RECONCILE",
                            result = "FAILED",
                            verification = "No clean-state claim made",
                        ),
                    )
                }
        }.start()
    }

    fun stop() {
        if (!started.compareAndSet(true, false)) return
        runCatching { appContext.unregisterReceiver(receiver) }
    }

    private fun reconcileAtProcessStart() {
        val current = currentPackageVersions()
        val previous = baseline.readAll()

        if (previous.isEmpty()) {
            baseline.replaceAll(current)
            audit.append(
                AuditEvent(
                    timestampEpochMs = System.currentTimeMillis(),
                    event = "INSTALL_GUARD_BASELINE_INITIALIZED",
                    source = "install-guard",
                    risk = RiskLevel.SAFE,
                    evidence = listOf("packages=${current.size}"),
                    action = "BASELINE",
                    result = "INITIALIZED",
                    verification = "Initial baseline stored without inventing historical install events",
                ),
            )
            return
        }

        current.forEach { (packageName, fingerprint) ->
            if (packageName == appContext.packageName) return@forEach
            if (previous[packageName] != fingerprint) {
                inspectOne(packageName, InstallObservationSource.PROCESS_START_RECONCILIATION)
            }
        }

        baseline.replaceAll(current)
    }

    private fun currentPackageVersions(): Map<String, String> = installedPackagesLightweight()
        .associate { packageInfo -> packageInfo.packageName to packageInfo.lastUpdateTime.toString() }

    private fun installedPackagesLightweight(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(0)
        }

    private fun inspectOne(packageName: String, source: InstallObservationSource) {
        val snapshot = inspector.collectPackage(packageName)
        if (snapshot == null) {
            audit.append(
                AuditEvent(
                    timestampEpochMs = System.currentTimeMillis(),
                    event = "INSTALL_GUARD_PACKAGE_UNAVAILABLE",
                    source = packageName,
                    risk = RiskLevel.LOW,
                    evidence = emptyList(),
                    action = "ANALYZE_PACKAGE",
                    result = "UNAVAILABLE",
                    verification = "Package could not be read; no safe/malicious verdict emitted",
                ),
            )
            return
        }
        inspectSnapshot(snapshot, source)
    }

    private fun inspectSnapshot(snapshot: AppSnapshot, source: InstallObservationSource) {
        val assessment = riskEngine.assess(snapshot)

        audit.append(
            AuditEvent(
                timestampEpochMs = System.currentTimeMillis(),
                event = "INSTALL_GUARD_PACKAGE_ANALYZED",
                source = snapshot.packageName,
                risk = assessment.riskLevel,
                evidence = assessment.evidence.map { it.id },
                action = "ANALYZE_PACKAGE",
                result = "COMPLETED",
                verification = "Package snapshot and deterministic assessment stored in audit event",
            ),
        )

        if (assessment.riskLevel == RiskLevel.HIGH || assessment.riskLevel == RiskLevel.CRITICAL) {
            alert.publish(assessment)
        }

        onFinding(
            InstallGuardFinding(
                packageName = snapshot.packageName,
                source = source,
                assessment = assessment,
            ),
        )
    }

    private fun refreshBaselineFor(packageName: String) {
        val packageInfo = runCatching { packageInfoLightweight(packageName) }.getOrNull() ?: return
        baseline.put(packageName, packageInfo.lastUpdateTime.toString())
    }

    private fun packageInfoLightweight(packageName: String): PackageInfo =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(packageName, PackageManager.PackageInfoFlags.of(0L))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, 0)
        }
}

private class InstallBaselineStore(context: Context) {
    private val preferences = context.getSharedPreferences("install-guard-baseline", Context.MODE_PRIVATE)

    fun readAll(): Map<String, String> = preferences.all.mapNotNull { (key, value) ->
        (value as? String)?.let { key to it }
    }.toMap()

    fun replaceAll(values: Map<String, String>) {
        preferences.edit().clear().apply {
            values.forEach { (key, value) -> putString(key, value) }
        }.apply()
    }

    fun put(packageName: String, fingerprint: String) {
        preferences.edit().putString(packageName, fingerprint).apply()
    }
}
