package pl.siedlar.securityguardian

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import pl.siedlar.securityguardian.ai.CopilotContext
import pl.siedlar.securityguardian.ai.GroundedCopilot
import pl.siedlar.securityguardian.command.BrokerResult
import pl.siedlar.securityguardian.command.android.AndroidSecurityCommandRuntime

class CopilotActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val runtime = AndroidSecurityCommandRuntime(applicationContext)
        val copilot = GroundedCopilot()

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                var input by remember { mutableStateOf("") }
                var state by remember { mutableStateOf<CopilotUiState>(CopilotUiState.Idle) }

                CopilotScreen(
                    input = input,
                    state = state,
                    onInputChanged = { input = it },
                    onSend = {
                        val message = input.trim()
                        if (message.isBlank() || state is CopilotUiState.Working) return@CopilotScreen

                        val plan = copilot.plan(
                            userText = message,
                            context = CopilotContext(
                                facts = emptyList(),
                                allowedActions = runtime.supportedActions,
                            ),
                        )

                        val command = plan.proposedCommand
                        if (command == null) {
                            state = CopilotUiState.Answer(
                                explanation = plan.explanation,
                                result = null,
                                verification = null,
                                warning = plan.warnings.joinToString().ifBlank { null },
                            )
                            return@CopilotScreen
                        }

                        state = CopilotUiState.Working(plan.explanation)
                        Thread {
                            val next = runCatching { runtime.submit(command) }
                                .fold(
                                    onSuccess = { result -> result.toUiState(plan.explanation) },
                                    onFailure = { error ->
                                        CopilotUiState.Answer(
                                            explanation = plan.explanation,
                                            result = "Polecenie nie zostało ukończone: ${error.message ?: error::class.java.simpleName}",
                                            verification = "Brak pozytywnej weryfikacji.",
                                            warning = "EXECUTION_FAILED",
                                        )
                                    },
                                )
                            runOnUiThread { state = next }
                        }.start()
                    },
                )
            }
        }
    }
}

private sealed interface CopilotUiState {
    data object Idle : CopilotUiState
    data class Working(val explanation: String) : CopilotUiState
    data class Answer(
        val explanation: String,
        val result: String?,
        val verification: String?,
        val warning: String?,
    ) : CopilotUiState
}

private fun BrokerResult.toUiState(explanation: String): CopilotUiState.Answer = when (this) {
    is BrokerResult.Completed -> CopilotUiState.Answer(
        explanation = explanation,
        result = "${execution.resultCode}: ${execution.detail}",
        verification = if (verification.verified) {
            "ZWERYFIKOWANO: ${verification.detail}"
        } else {
            "NIE ZWERYFIKOWANO: ${verification.detail}"
        },
        warning = null,
    )

    is BrokerResult.Denied -> CopilotUiState.Answer(
        explanation = explanation,
        result = "ODMOWA: ${decision.reason}",
        verification = "Nie uruchomiono executora.",
        warning = decision.type.name,
    )

    is BrokerResult.AwaitingHumanGate -> CopilotUiState.Answer(
        explanation = explanation,
        result = "WYMAGANE POTWIERDZENIE: $reason",
        verification = "Operacja nie została wykonana bez Human Gate.",
        warning = policy.humanGate.name,
    )
}

@Composable
private fun CopilotScreen(
    input: String,
    state: CopilotUiState,
    onInputChanged: (String) -> Unit,
    onSend: () -> Unit,
) {
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
                    "AI Security Copilot",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                )
                Text(
                    "P4: lokalny parser bez chmury. Każda akcja przechodzi przez Policy Engine, capability check, executor i verifier.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(containerColor = Color.White),
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("Przykłady", fontWeight = FontWeight.Bold)
                        Text("• Zeskanuj telefon")
                        Text("• Czy ktoś mnie podsłuchuje?")
                        Text("• Sprawdź link https://example.com")
                        Text("• Zablokuj domenę bad.example")
                        Text("• Sprawdź aplikację com.example.app")
                    }
                }
            }

            item {
                OutlinedTextField(
                    modifier = Modifier.fillMaxWidth(),
                    value = input,
                    onValueChange = onInputChanged,
                    minLines = 2,
                    maxLines = 5,
                    label = { Text("Napisz polecenie bezpieczeństwa") },
                )
            }

            item {
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = input.isNotBlank() && state !is CopilotUiState.Working,
                    onClick = onSend,
                ) {
                    if (state is CopilotUiState.Working) {
                        CircularProgressIndicator(strokeWidth = 2.dp)
                    } else {
                        Text("WYKONAJ BEZPIECZNIE")
                    }
                }
            }

            when (state) {
                CopilotUiState.Idle -> item {
                    Text("Copilot nie ma arbitralnego dostępu do shella ani systemu.")
                }

                is CopilotUiState.Working -> item {
                    ResultCard(
                        title = "Wykonywanie",
                        lines = listOf(state.explanation, "Security Engine wykonuje i weryfikuje polecenie…"),
                    )
                }

                is CopilotUiState.Answer -> item {
                    ResultCard(
                        title = "Wynik",
                        lines = listOfNotNull(
                            state.explanation,
                            state.result,
                            state.verification,
                            state.warning?.let { "Ostrzeżenie: $it" },
                        ),
                    )
                }
            }
        }
    }
}

@Composable
private fun ResultCard(
    title: String,
    lines: List<String>,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(title, fontWeight = FontWeight.Bold)
            lines.forEach { Text(it) }
        }
    }
}
