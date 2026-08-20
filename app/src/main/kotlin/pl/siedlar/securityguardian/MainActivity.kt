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
import pl.siedlar.securityguardian.core.DeviceScanReport
import pl.siedlar.securityguardian.core.FullScanService
import pl.siedlar.securityguardian.core.RiskEngine
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.inspector.AndroidAppInspector
import pl.siedlar.securityguardian.notifications.AndroidSecurityAlertSink

class MainActivity : ComponentActivity() {
    private lateinit var scanService: FullScanService

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        requestNotificationPermissionWhenNeeded()

        scanService = FullScanService(
            inventory = AndroidAppInspector(applicationContext),
            riskEngine = RiskEngine(),
            auditSink = JsonlAuditLogger(applicationContext),
            alertSink = AndroidSecurityAlertSink(applicationContext),
        )

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                var scanState by remember { mutableStateOf<ScanUiState>(ScanUiState.Idle) }

                GuardianScreen(
                    state = scanState,
                    onScan = {
                        if (scanState is ScanUiState.Scanning) return@GuardianScreen
                        scanState = ScanUiState.Scanning
                        Thread {
                            val nextState = runCatching { scanService.run() }
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

    private fun requestNotificationPermissionWhenNeeded() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 1001)
        }
    }
}

private sealed interface ScanUiState {
    data object Idle : ScanUiState
    data object Scanning : ScanUiState
    data class Complete(val report: DeviceScanReport) : ScanUiState
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
                    text = "P0: aplikacje, źródła instalacji, certyfikaty, hash APK, uprawnienia, Accessibility i Device Admin.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            item {
                StatusCard(state)
            }

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
                val riskyApps = state.report.assessments.filter { it.riskScore > 0 }.take(12)
                item {
                    Text(
                        "Najwyższe wykryte ryzyko",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.SemiBold,
                    )
                }

                if (riskyApps.isEmpty()) {
                    item {
                        Text(
                            "W zakresie P0 nie znaleziono aplikacji z podwyższonym wynikiem ryzyka. To nie jest jeszcze dowód czystości całego urządzenia.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                } else {
                    items(riskyApps, key = { it.app.packageName }) { assessment ->
                        RiskCard(assessment)
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
                    Text("Uruchom skan, aby zbudować pierwszy rzeczywisty baseline bezpieczeństwa aplikacji.")
                }

                ScanUiState.Scanning -> {
                    Text("Skanowanie w toku", fontWeight = FontWeight.Bold)
                    Text("Analizuję rzeczywiste pakiety i ich dostępne sygnały bezpieczeństwa. UI pozostaje aktywne.")
                }

                is ScanUiState.Error -> {
                    Text("Skan nie został ukończony", fontWeight = FontWeight.Bold)
                    Text(state.message)
                }

                is ScanUiState.Complete -> {
                    val report = state.report
                    Text("App Security Score", style = MaterialTheme.typography.labelLarge)
                    Text(
                        "${report.appSecurityScore}/100",
                        style = MaterialTheme.typography.displaySmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                    ) {
                        Text("Aplikacje: ${report.assessments.size}")
                        Text("HIGH/CRITICAL: ${report.highOrCriticalCount}")
                    }
                    Text(
                        "Score P0 = 100 minus najwyższy realny wynik ryzyka aplikacji. Pełny Security Score urządzenia powstanie po wdrożeniu prywatności, sieci i integralności.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
        }
    }
}

@Composable
private fun RiskCard(assessment: AppAssessment) {
    val accent = when (assessment.riskLevel) {
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
                    Text(assessment.app.label, fontWeight = FontWeight.SemiBold)
                    Text(
                        assessment.app.packageName,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                Text(
                    "${assessment.riskLevel.name} ${assessment.riskScore}/100",
                    color = accent,
                    fontWeight = FontWeight.Bold,
                )
            }

            assessment.evidence.take(3).forEach { evidence ->
                Text("• ${evidence.title}: ${evidence.detail}", style = MaterialTheme.typography.bodySmall)
            }

            Text(
                "Pewność oceny: ${assessment.confidence}%",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
