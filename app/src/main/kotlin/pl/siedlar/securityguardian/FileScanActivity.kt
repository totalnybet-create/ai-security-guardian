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
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import pl.siedlar.securityguardian.malware.FileDisposition
import pl.siedlar.securityguardian.malware.MalwareAssessment

class FileScanActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val sharedUri = extractSharedUri(intent)
        val controller = FileScanController(applicationContext)

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                var state by remember {
                    mutableStateOf<FileScanUiState>(
                        if (sharedUri == null) {
                            FileScanUiState.Error("Nie otrzymano pliku do skanowania.")
                        } else {
                            FileScanUiState.Scanning
                        },
                    )
                }

                if (sharedUri != null && state is FileScanUiState.Scanning) {
                    remember(sharedUri) {
                        Thread {
                            val nextState = runCatching { controller.scan(sharedUri) }
                                .fold(
                                    onSuccess = { FileScanUiState.Complete(it) },
                                    onFailure = { FileScanUiState.Error(it.message ?: "Nie udało się odczytać pliku.") },
                                )
                            runOnUiThread { state = nextState }
                        }.apply { start() }
                    }
                }

                FileScanScreen(state)
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
    data class Complete(val assessment: MalwareAssessment) : FileScanUiState
    data class Error(val message: String) : FileScanUiState
}

@Composable
private fun FileScanScreen(state: FileScanUiState) {
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

                is FileScanUiState.Complete -> FileAssessmentCard(state.assessment)
            }
        }
    }
}

@Composable
private fun FileAssessmentCard(assessment: MalwareAssessment) {
    val actionText = when (assessment.recommendedDisposition) {
        FileDisposition.ALLOW -> "Brak sygnałów wymagających blokady w aktualnym zakresie analizy."
        FileDisposition.WATCH -> "Nie otwieraj pochopnie. Wymagana jest dodatkowa weryfikacja."
        FileDisposition.BLOCK -> "Nie otwieraj tego pliku do czasu dodatkowej weryfikacji."
        FileDisposition.QUARANTINE -> "Traktuj plik jako wysokiego ryzyka i nie otwieraj go."
        FileDisposition.DELETE -> "Usunięcie wymaga osobnego, jednoznacznego potwierdzenia użytkownika."
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
        }
    }
}
