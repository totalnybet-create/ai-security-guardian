package pl.siedlar.securityguardian

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import pl.siedlar.securityguardian.quarantine.AndroidFileQuarantine
import pl.siedlar.securityguardian.quarantine.QuarantineOutcome
import pl.siedlar.securityguardian.quarantine.QuarantineRecord
import pl.siedlar.securityguardian.quarantine.RestoreResult

class QuarantineActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val vault = AndroidFileQuarantine(applicationContext)

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                var records by remember { mutableStateOf(vault.listRecords()) }
                var pendingRestore by remember { mutableStateOf<QuarantineRecord?>(null) }
                var restoring by remember { mutableStateOf(false) }
                var lastRestore by remember { mutableStateOf<RestoreResult?>(null) }

                val restoreLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.CreateDocument("application/octet-stream"),
                ) { destinationUri ->
                    val record = pendingRestore
                    if (destinationUri == null || record == null) {
                        pendingRestore = null
                        return@rememberLauncherForActivityResult
                    }

                    restoring = true
                    Thread {
                        val result = vault.restore(
                            record = record,
                            destinationUri = destinationUri,
                            removeVaultCopyAfterVerification = false,
                        )
                        runOnUiThread {
                            lastRestore = result
                            records = vault.listRecords()
                            pendingRestore = null
                            restoring = false
                        }
                    }.start()
                }

                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = Color(0xFFF7F8FA),
                ) {
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(18.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        item {
                            Text(
                                "Sejf zagrożeń",
                                style = MaterialTheme.typography.headlineMedium,
                                fontWeight = FontWeight.Bold,
                            )
                            Text(
                                "Prywatna pamięć aplikacji. CONTAINED oznacza, że oryginał został rzeczywiście usunięty po weryfikacji SHA-256; VAULT_COPY_ONLY oznacza, że oryginał nadal istnieje.",
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )
                        }

                        if (restoring) {
                            item {
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = CardDefaults.cardColors(containerColor = Color.White),
                                ) {
                                    Column(modifier = Modifier.padding(16.dp)) {
                                        CircularProgressIndicator()
                                        Text("Przywracam i ponownie sprawdzam SHA-256…")
                                    }
                                }
                            }
                        }

                        lastRestore?.let { restore ->
                            item {
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = CardDefaults.cardColors(containerColor = Color.White),
                                ) {
                                    Column(modifier = Modifier.padding(16.dp)) {
                                        Text("Przywracanie: ${restore.outcome.name}", fontWeight = FontWeight.Bold)
                                        Text(restore.detail)
                                    }
                                }
                            }
                        }

                        if (records.isEmpty()) {
                            item {
                                Text("Sejf jest pusty. Brak zapisanych rekordów kwarantanny.")
                            }
                        } else {
                            items(records, key = { record -> record.id }) { record ->
                                Card(
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = CardDefaults.cardColors(containerColor = Color.White),
                                ) {
                                    Column(
                                        modifier = Modifier.padding(16.dp),
                                        verticalArrangement = Arrangement.spacedBy(6.dp),
                                    ) {
                                        Text(record.originalDisplayName, fontWeight = FontWeight.Bold)
                                        Text("${record.riskLevel} ${record.riskScore}/100 · ${record.outcome.name}")
                                        Text("SHA-256: ${record.sha256}", style = MaterialTheme.typography.bodySmall)
                                        Text("Źródło: ${record.source ?: "nieznane"}", style = MaterialTheme.typography.bodySmall)
                                        Text(record.detail, style = MaterialTheme.typography.bodySmall)
                                        record.lastRestoreOutcome?.let { outcome ->
                                            Text("Ostatnie przywracanie: ${outcome.name}", style = MaterialTheme.typography.bodySmall)
                                        }

                                        if (record.outcome != QuarantineOutcome.FAILED && !restoring) {
                                            Button(
                                                modifier = Modifier.fillMaxWidth(),
                                                onClick = {
                                                    pendingRestore = record
                                                    restoreLauncher.launch(record.originalDisplayName)
                                                },
                                            ) {
                                                Text("PRZYWRÓĆ DO WYBRANEGO MIEJSCA")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
