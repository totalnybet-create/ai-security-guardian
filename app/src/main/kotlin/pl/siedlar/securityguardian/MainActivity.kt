package pl.siedlar.securityguardian

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import pl.siedlar.securityguardian.audit.JsonlAuditLogger
import pl.siedlar.securityguardian.core.AppAssessment
import pl.siedlar.securityguardian.core.AppInventorySource
import pl.siedlar.securityguardian.core.AppSnapshot
import pl.siedlar.securityguardian.core.DeviceScanReport
import pl.siedlar.securityguardian.core.FullScanService
import pl.siedlar.securityguardian.core.RiskEngine
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.inspector.AndroidAppInspector
import pl.siedlar.securityguardian.inspector.AndroidPrivacyInspector
import pl.siedlar.securityguardian.notifications.AndroidPrivacyAlertSink
import pl.siedlar.securityguardian.notifications.AndroidSecurityAlertSink
import pl.siedlar.securityguardian.privacy.PrivacyAssessment
import pl.siedlar.securityguardian.privacy.PrivacyRiskEngine
import pl.siedlar.securityguardian.privacy.PrivacyScanReport
import pl.siedlar.securityguardian.privacy.PrivacyScanService

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        requestNotificationPermissionWhenNeeded()

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                var scanState by remember { mutableStateOf<ScanUiState>(ScanUiState.Idle) }

                GuardianScreen(
                    state = scanState,
                    onScan = {
                        if (scanState is ScanUiState.Scanning) return@GuardianScreen
                        scanState = ScanUiState.Scanning

                        Thread {
                            val nextState = runCatching { runVerifiedScan() }
                                .fold(
                                    onSuccess = { ScanUiState.Complete(it) },
                                    onFailure = { ScanUiState.Error(it.message ?: "Nieznany błąd skanowania") },
                                )
                            runOnUiThread { scanState = nextState }
                        }.start()
                    },
                )
            }
        }
    }

    private fun runVerifiedScan(): VerifiedScanBundle {
        val rawInventory = AndroidAppInspector(applicationContext)
        val sharedInventory = object : AppInventorySource {
            private var cache: List<AppSnapshot>? = null

            override fun collect(): List<AppSnapshot> {
                cache?.let { return it }
                return rawInventory.collect().also { cache = it }
            }
        }

        val audit = JsonlAuditLogger(applicationContext)

        val appReport = FullScanService(
            inventory = sharedInventory,
            riskEngine = RiskEngine(),
            auditSink = audit,
            alertSink = AndroidSecurityAlertSink(applicationContext),
        ).run()

        val privacyReport = PrivacyScanService(
            inventory = AndroidPrivacyInspector(applicationContext, sharedInventory),
            riskEngine = PrivacyRiskEngine(),
            auditSink = audit,
            alertSink = AndroidPrivacyAlertSink(applicationContext),
        ).run()

        return VerifiedScanBundle(
            appReport = appReport,
            privacyReport = privacyReport,
        )
    }

    private fun requestNotificationPermissionWhenNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
    }
}

private data class VerifiedScanBundle(
    val appReport: DeviceScanReport,
    val privacyReport: PrivacyScanReport,
) {
    val securityScoreP1: Int
        get() = minOf(appReport.appSecurityScore, privacyReport.privacySecurityScore)

    val highOrCriticalCount: Int
        get() = appReport.highOrCriticalCount + privacyReport.highOrCriticalCount
}

private sealed interface ScanUiState {
    data object Idle : ScanUiState
    data object Scanning : ScanUiState
    data class Complete(val report: VerifiedScanBundle) : ScanUiState
    data class Error(val message: String) : ScanUiState
}

@Composable
private fun GuardianScreen(
    state: ScanUiState,
    onScan: () -> Unit,
) {
    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFFF7F8FA),
    ) {
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 18.dp, vertical = 20.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                Text(
                    text = "AI Security Guardian",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = "Zweryfikowany zakres P1: aplikacje i prywatność. Pozostałe warstwy są dodawane etapami.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            item { StatusCard(state) }

            item {
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = state !is ScanUiState.Scanning,
                    onClick = onScan,
                ) {
                    if (state is ScanUiState.Scanning) {
                        CircularProgressIndicator(
                            modifier = Modifier.height(20.dp),
                            strokeWidth = 2.dp,
                        )
                    } else {
                        Text("SKANUJ CAŁY TELEFON")
                    }
                }
            }

            if (state is ScanUiState.Complete) {
                val appRisks = state.report.appReport.assessments.filter { it.riskScore > 0 }.take(10)
                val privacyRisks = state.report.privacyReport.assessments.filter { it.riskScore > 0 }.take(10)

                item {
                    Text(
                        "Prywatność",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                if (privacyRisks.isEmpty()) {
                    item {
                        Text(
                            "W dostępnym zakresie P1 nie wykryto podwyższonego ryzyka prywatności.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                } else {
                    items(privacyRisks, key = { "privacy:${it.snapshot.packageName}" }) { assessment ->
                        PrivacyRiskCard(assessment)
                    }
                }

                item {
                    Text(
                        "Aplikacje",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }
                if (appRisks.isEmpty()) {
                    item {
                        Text(
                            "W dostępnym zakresie P0 nie wykryto aplikacji z podwyższonym wynikiem ryzyka.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                } else {
                    items(appRisks, key = { "app:${it.app.packageName}" }) { assessment ->
                        AppRiskCard(assessment)
                    }
                }
            }
        }
    }
}

@Composable
private fun StatusCard(state: ScanUiState) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            when (state) {
                ScanUiState.Idle -> {
                    Text("Brak zweryfikowanego skanu", fontWeight = FontWeight.Bold)
                    Text("Uruchom skan, aby odczytać aktualny stan aplikacji i prywatności.")
                }

                ScanUiState.Scanning -> {
                    Text("Skanowanie w toku", fontWeight = FontWeight.Bold)
                    Text("Czytam jeden wspólny snapshot aplikacji, następnie analizuję bezpieczeństwo i prywatność. UI pozostaje aktywne.")
                }

                is ScanUiState.Error -> {
                    Text("Skan nie został ukończony", fontWeight = FontWeight.Bold)
                    Text(state.message)
                }

                is ScanUiState.Complete -> {
                    val report = state.report
                    Text("SECURITY SCORE P1 · zakres 2/7", style = MaterialTheme.typography.labelLarge)
                    Text(
                        "${report.securityScoreP1}/100",
                        style = MaterialTheme.typography.displaySmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text("Aplikacje: ${report.appReport.appSecurityScore}/100")
                        Text("Prywatność: ${report.privacyReport.privacySecurityScore}/100")
                    }
                    Text(
                        if (report.highOrCriticalCount == 0) {
                            "Brak HIGH/CRITICAL w aktualnie zweryfikowanych warstwach. To nie jest jeszcze dowód czystości całego urządzenia."
                        } else {
                            "Wykryto ${report.highOrCriticalCount} wyników HIGH/CRITICAL w zweryfikowanych warstwach. Sprawdź szczegóły poniżej."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Text(
                        "Wynik P1 jest równy słabszej z dwóch kategorii, aby wysoki problem prywatności nie został ukryty przez dobry wynik aplikacji.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun PrivacyRiskCard(assessment: PrivacyAssessment) {
    RiskContainer(
        label = assessment.snapshot.label,
        packageName = assessment.snapshot.packageName,
        riskLevel = assessment.riskLevel,
        riskScore = assessment.riskScore,
        confidence = assessment.confidence,
        evidence = assessment.evidence.take(3).map { "${it.title}: ${it.detail}" },
    )
}

@Composable
private fun AppRiskCard(assessment: AppAssessment) {
    RiskContainer(
        label = assessment.app.label,
        packageName = assessment.app.packageName,
        riskLevel = assessment.riskLevel,
        riskScore = assessment.riskScore,
        confidence = assessment.confidence,
        evidence = assessment.evidence.take(3).map { "${it.title}: ${it.detail}" },
    )
}

@Composable
private fun RiskContainer(
    label: String,
    packageName: String,
    riskLevel: RiskLevel,
    riskScore: Int,
    confidence: Int,
    evidence: List<String>,
) {
    val accent = when (riskLevel) {
        RiskLevel.CRITICAL -> Color(0xFFB3261E)
        RiskLevel.HIGH -> Color(0xFF9A4A00)
        RiskLevel.MEDIUM -> Color(0xFF7A5C00)
        RiskLevel.LOW -> Color(0xFF335C67)
        RiskLevel.SAFE -> Color(0xFF2E6B4F)
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
    ) {
        Column(
            modifier = Modifier.padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(label, fontWeight = FontWeight.SemiBold)
                    Text(
                        packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    "${riskLevel.name} $riskScore/100",
                    color = accent,
                    fontWeight = FontWeight.Bold,
                )
            }

            evidence.forEach { detail ->
                Text("• $detail", style = MaterialTheme.typography.bodySmall)
            }

            Text(
                "Pewność oceny: $confidence%",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
