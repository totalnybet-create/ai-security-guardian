package pl.siedlar.securityguardian

import android.content.Intent
import android.net.Uri
import android.os.Build
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
import androidx.compose.material3.CircularProgressIndicator
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
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.malware.FileDisposition
import pl.siedlar.securityguardian.malware.MalwareAssessment
import pl.siedlar.securityguardian.quarantine.QuarantineRecord

class FileScanActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sharedUri = extractSharedUri(intent)
        val controller = FileScanController(applicationContext)
        val state = mutableStateOf<FileScanUiState>(
            if (sharedUri == null) {
                FileScanUiState.Error("Nie otrzymano pliku do skanowania.")
            } else {
                FileScanUiState.Scanning
            },
        )

        if (sharedUri != null) {
            Thread {
                val nextState = runCatching { controller.scan(sharedUri) }
                    .fold(
                        onSuccess = { FileScanUiState.Complete(it) },
                        onFailure = { FileScanUiState.Error(it.message ?: "Nie udało się odczytać pliku.") },
                    )
                runOnUiThread { state.value = nextState }
            }.start()
        }

        fun runQuarantine(removeOriginal: Boolean) {
            val uri = sharedUri ?: return
            val complete = state.value as? FileScanUiState.Complete ?: return
            if (complete.quarantining) return
            state.value = complete.copy(quarantining = true)

            Thread {
                val result = runCatching {
                    controller.quarantine(
                        uri = uri,
                        assessment = complete.assessment,
                        removeOriginalAfterVerifiedCopy = removeOriginal,
                    )
                }
                runOnUiThread {
                    state.value = result.fold(
                        onSuccess = { record -> complete.copy(quarantining = false, quarantineRecord = record) },
                        onFailure = { error ->
                            complete.copy(
                                quarantining = false,
                                quarantineError = error.message ?: "Nie udało się wykonać operacji sejfu.",
                            )
                        },
                    )
                }
            }.start()
        }

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                FileScanScreen(
                    state = state.value,
                    onVaultCopy = { runQuarantine(removeOriginal = false) },
                    onContainOriginal = { runQuarantine(removeOriginal = true) },
                )
            }
        }
    }

    private fun extractSharedUri(intent: Intent): Uri? {
        intent.data?.let { return it }
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra(Intent.EXTRA_STREAM)
        }
    }
}

private sealed interface FileScanUiState {
    data object Scanning : FileScanUiState
    data class Complete(
        val assessment: MalwareAssessment,
        val quarantining: Boolean = false,
        val quarantineRecord: QuarantineRecord? = null,
        val quarantineError: String? = null,
    ) : FileScanUiState

    data class Error(val message: String) : FileScanUiState
}

@Composable
private fun FileScanScreen(
    state: FileScanUiState,
    onVaultCopy: () -> Unit,
    onContainOriginal: () -> Unit,
) {
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
                "Skanowanie pliku",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold,
            )
            Text(
                "Analiza lokalna. Plik nie jest wysyłany do zewnętrznego dostawcy reputacji w tym etapie.",
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            when (state) {
                FileScanUiState.Scanning -> Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        CircularProgressIndicator()
                        Text("Liczenie SHA-256 i analiza dostępnych sygnałów statycznych…")
                    }
                }

                is FileScanUiState.Error -> Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                ) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Text("Skan nie został ukończony", fontWeight = FontWeight.Bold)
                        Text(state.message)
                    }
                }

                is FileScanUiState.Complete -> FileAssessmentCard(
                    state = state,
                    onVaultCopy = onVaultCopy,
                    onContainOriginal = onContainOriginal,
                )
            }
        }
    }
}

@Composable
private fun FileAssessmentCard(
    state: FileScanUiState.Complete,
    onVaultCopy: () -> Unit,
    onContainOriginal: () -> Unit,
) {
    val assessment = state.assessment
    var showContainConfirmation by remember { mutableStateOf(false) }
    val actionText = when (assessment.recommendedDisposition) {
        FileDisposition.ALLOW -> "Brak sygnałów wymagających blokady w aktualnym zakresie analizy."
        FileDisposition.WATCH -> "Nie otwieraj pochopnie. Wymagana jest dodatkowa weryfikacja."
        FileDisposition.BLOCK -> "Nie otwieraj tego pliku do czasu dodatkowej weryfikacji."
        FileDisposition.QUARANTINE -> "Traktuj plik jako wysokiego ryzyka i nie otwieraj go."
        FileDisposition.DELETE -> "Usunięcie wymaga osobnego, jednoznacznego potwierdzenia użytkownika."
    }

    if (showContainConfirmation) {
        AlertDialog(
            onDismissRequest = { showContainConfirmation = false },
            title = { Text("Odizolować oryginał?") },
            text = {
                Text(
                    "Guardian najpierw zapisze kopię w prywatnym sejfie i sprawdzi SHA-256. Dopiero po poprawnej weryfikacji spróbuje usunąć oryginalny dokument. Jeśli Android lub dostawca pliku nie pozwoli na usunięcie, wynik będzie VAULT_COPY_ONLY, a nie fałszywe CONTAINED.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        showContainConfirmation = false
                        onContainOriginal()
                    },
                ) {
                    Text("POTWIERDZAM IZOLACJĘ")
                }
            },
            dismissButton = {
                TextButton(onClick = { showContainConfirmation = false }) {
                    Text("ANULUJ")
                }
            },
        )
    }

    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(assessment.artifact.displayName, fontWeight = FontWeight.Bold)
            Text("Ryzyko: ${assessment.riskLevel.name} ${assessment.riskScore}/100")
            Text("Pewność: ${assessment.confidence}%")
            Text("SHA-256: ${assessment.artifact.sha256}", style = MaterialTheme.typography.bodySmall)
            Text(actionText, fontWeight = FontWeight.SemiBold)

            if (assessment.reputation.isEmpty()) {
                Text(
                    "Reputacja zewnętrzna: NIE SPRAWDZONO — aktywna jest wyłącznie analiza lokalna.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            assessment.evidence.take(5).forEach { evidence ->
                Text("• ${evidence.detail}", style = MaterialTheme.typography.bodySmall)
            }

            if (state.quarantining) {
                CircularProgressIndicator()
                Text("Weryfikuję kopię sejfu…")
            } else {
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = onVaultCopy,
                ) {
                    Text("KOPIA DO SEJFU")
                }

                if (assessment.riskLevel == RiskLevel.HIGH || assessment.riskLevel == RiskLevel.CRITICAL) {
                    Button(
                        modifier = Modifier.fillMaxWidth(),
                        onClick = { showContainConfirmation = true },
                    ) {
                        Text("ODIZOLUJ ORYGINAŁ")
                    }
                }
            }

            state.quarantineRecord?.let { record ->
                Text(
                    "Sejf: ${record.outcome.name}",
                    fontWeight = FontWeight.Bold,
                )
                Text(record.detail, style = MaterialTheme.typography.bodySmall)
            }

            state.quarantineError?.let { error ->
                Text(
                    "Operacja sejfu nie została ukończona: $error",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }
    }
}
