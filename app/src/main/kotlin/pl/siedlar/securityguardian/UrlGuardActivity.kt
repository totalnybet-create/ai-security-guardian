package pl.siedlar.securityguardian

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import pl.siedlar.securityguardian.audit.JsonlAuditLogger
import pl.siedlar.securityguardian.core.AuditEvent
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.url.UrlAssessment
import pl.siedlar.securityguardian.url.UrlRiskEngine
import pl.siedlar.securityguardian.url.UrlRiskLevel
import pl.siedlar.securityguardian.url.UrlTextExtractor

class UrlGuardActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sharedText = buildString {
            intent.getCharSequenceExtra(Intent.EXTRA_SUBJECT)?.toString()?.takeIf(String::isNotBlank)?.let {
                append(it).append('\n')
            }
            intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()?.let(::append)
        }
        val candidate = UrlTextExtractor().firstCandidate(sharedText)
        val assessment = candidate?.let { UrlRiskEngine().assess(it) }
        assessment?.let(::auditAssessment)

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                UrlGuardScreen(
                    assessment = assessment,
                    onOpen = { openAssessment(it, confirmedRisk = false) },
                    onOpenConfirmed = { openAssessment(it, confirmedRisk = true) },
                    onClose = ::finish,
                )
            }
        }
    }

    private fun openAssessment(assessment: UrlAssessment, confirmedRisk: Boolean) {
        val scheme = assessment.scheme
        val host = assessment.normalizedHost
        if (scheme !in setOf("http", "https") || host == null) return
        if (!confirmedRisk && assessment.riskLevel > UrlRiskLevel.LOW) return

        val result = runCatching {
            startActivity(
                Intent(Intent.ACTION_VIEW, Uri.parse(assessment.input)).apply {
                    addCategory(Intent.CATEGORY_BROWSABLE)
                },
            )
        }

        JsonlAuditLogger(applicationContext).append(
            AuditEvent(
                timestampEpochMs = System.currentTimeMillis(),
                event = "URL_GUARD_OPEN_DECISION",
                source = host,
                risk = assessment.riskLevel.toCoreRisk(),
                evidence = assessment.evidence.map { it.id },
                action = if (confirmedRisk) "OPEN_AFTER_HUMAN_GATE" else "OPEN_LOW_RISK",
                result = if (result.isSuccess) "INTENT_DISPATCHED" else "FAILED",
                verification = if (result.isSuccess) {
                    "Android ACTION_VIEW dispatched; browser navigation result is outside Guardian control"
                } else {
                    "No browser-open success claim made"
                },
            ),
        )
        if (result.isSuccess) finish()
    }

    private fun auditAssessment(assessment: UrlAssessment) {
        JsonlAuditLogger(applicationContext).append(
            AuditEvent(
                timestampEpochMs = System.currentTimeMillis(),
                event = "URL_GUARD_ASSESSED",
                source = assessment.normalizedHost ?: "unresolved-url",
                risk = assessment.riskLevel.toCoreRisk(),
                evidence = assessment.evidence.map { it.id },
                action = "ASSESS_URL",
                result = "COMPLETED",
                verification = "Deterministic local URL assessment; no cloud reputation claim",
            ),
        )
    }
}

@Composable
private fun UrlGuardScreen(
    assessment: UrlAssessment?,
    onOpen: (UrlAssessment) -> Unit,
    onOpenConfirmed: (UrlAssessment) -> Unit,
    onClose: () -> Unit,
) {
    var showRiskConfirmation by remember { mutableStateOf(false) }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = Color(0xFFF7F8FA),
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(18.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                "Sprawdź link",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "Analiza lokalna przed otwarciem. Guardian nie wysyła tego linku do zewnętrznego dostawcy reputacji w tym etapie.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            if (assessment == null) {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("Nie znaleziono linku do analizy", fontWeight = FontWeight.Bold)
                        Text("Udostępniony tekst nie zawiera obsługiwanego adresu HTTP(S) ani jawnego niebezpiecznego schematu.")
                    }
                }
                OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = onClose) {
                    Text("ZAMKNIJ")
                }
                return@Column
            }

            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(containerColor = Color.White),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(
                        "${assessment.riskLevel.name} · ${assessment.riskScore}/100",
                        fontWeight = FontWeight.Bold,
                    )
                    Text(assessment.normalizedHost ?: assessment.input)
                    Text("Pewność oceny: ${assessment.confidence}%")

                    if (assessment.evidence.isEmpty()) {
                        Text("Brak lokalnych sygnałów podwyższonego ryzyka.")
                    } else {
                        assessment.evidence.take(6).forEach { evidence ->
                            Text("• ${evidence.detail}", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }

            val isWeb = assessment.scheme in setOf("http", "https") && assessment.normalizedHost != null
            when {
                !isWeb -> {
                    Text(
                        "Guardian nie otworzy tego schematu. Obsługiwane do otwierania są wyłącznie HTTP i HTTPS.",
                        color = MaterialTheme.colorScheme.error,
                    )
                }

                assessment.riskLevel <= UrlRiskLevel.LOW -> Button(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { onOpen(assessment) },
                ) {
                    Text("OTWÓRZ LINK")
                }

                else -> Button(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = { showRiskConfirmation = true },
                ) {
                    Text("OTWÓRZ MIMO RYZYKA")
                }
            }

            OutlinedButton(modifier = Modifier.fillMaxWidth(), onClick = onClose) {
                Text("NIE OTWIERAJ")
            }
        }
    }

    if (assessment != null && showRiskConfirmation) {
        AlertDialog(
            onDismissRequest = { showRiskConfirmation = false },
            title = { Text("Otworzyć ryzykowny link?") },
            text = {
                Text(
                    "Guardian wykrył sygnały ${assessment.riskLevel.name}. Otwarcie nastąpi dopiero po tym potwierdzeniu. Sam wynik lokalny nie jest deklarowany jako dowód phishingu lub malware.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showRiskConfirmation = false
                        onOpenConfirmed(assessment)
                    },
                ) {
                    Text("POTWIERDZAM OTWARCIE")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRiskConfirmation = false }) {
                    Text("ANULUJ")
                }
            },
        )
    }
}

private fun UrlRiskLevel.toCoreRisk(): RiskLevel = when (this) {
    UrlRiskLevel.SAFE -> RiskLevel.SAFE
    UrlRiskLevel.LOW -> RiskLevel.LOW
    UrlRiskLevel.MEDIUM -> RiskLevel.MEDIUM
    UrlRiskLevel.HIGH -> RiskLevel.HIGH
    UrlRiskLevel.CRITICAL -> RiskLevel.CRITICAL
}
