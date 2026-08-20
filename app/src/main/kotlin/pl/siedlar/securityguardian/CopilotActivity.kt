package pl.siedlar.securityguardian

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
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
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import pl.siedlar.securityguardian.ai.CopilotContext
import pl.siedlar.securityguardian.ai.GroundedCopilot
import pl.siedlar.securityguardian.command.BrokerResult
import pl.siedlar.securityguardian.command.android.AndroidSecurityCommandRuntime
import pl.siedlar.securityguardian.voice.SpeechInputMode
import pl.siedlar.securityguardian.voice.SpeechOutputMode
import pl.siedlar.securityguardian.voice.SpokenReply
import pl.siedlar.securityguardian.voice.SpokenReplyComposer
import pl.siedlar.securityguardian.voice.VoiceInputEvent
import pl.siedlar.securityguardian.voice.VoiceSessionState
import pl.siedlar.securityguardian.voice.android.AndroidSpeechInput
import pl.siedlar.securityguardian.voice.android.AndroidSpeechOutput

class CopilotActivity : ComponentActivity() {
    private lateinit var runtime: AndroidSecurityCommandRuntime
    private lateinit var copilot: GroundedCopilot
    private lateinit var speechInput: AndroidSpeechInput
    private lateinit var speechOutput: AndroidSpeechOutput

    private var input by mutableStateOf("")
    private var state by mutableStateOf<CopilotUiState>(CopilotUiState.Idle)
    private var voice by mutableStateOf(VoiceUiState())

    private val microphonePermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            startVoiceCapture()
        } else {
            voice = voice.copy(
                sessionState = VoiceSessionState.ERROR,
                detail = "Brak zgody na mikrofon. Rozmowa głosowa nie została uruchomiona.",
            )
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        runtime = AndroidSecurityCommandRuntime(applicationContext)
        copilot = GroundedCopilot()
        speechInput = AndroidSpeechInput(applicationContext)
        speechOutput = AndroidSpeechOutput(
            context = applicationContext,
            allowNetworkFallback = false,
            onState = { nextState ->
                runOnUiThread {
                    voice = voice.copy(
                        sessionState = nextState,
                        inputMode = speechInput.mode(),
                        outputMode = speechOutput.mode(),
                    )
                }
            },
        )
        refreshVoiceCapabilities()

        setContent {
            MaterialTheme(colorScheme = lightColorScheme()) {
                CopilotScreen(
                    input = input,
                    state = state,
                    voice = voice,
                    onInputChanged = { input = it },
                    onSend = { executeMessage(input, speakReply = false) },
                    onVoice = ::requestVoiceCapture,
                    onStopVoice = {
                        speechInput.cancel()
                        speechOutput.stop()
                        voice = voice.copy(sessionState = VoiceSessionState.IDLE, detail = "Sesja głosowa zatrzymana.")
                    },
                )
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (::speechInput.isInitialized) refreshVoiceCapabilities()
    }

    override fun onDestroy() {
        if (::speechInput.isInitialized) speechInput.destroy()
        if (::speechOutput.isInitialized) speechOutput.shutdown()
        super.onDestroy()
    }

    private fun requestVoiceCapture() {
        if (state is CopilotUiState.Working) return
        if (checkSelfPermission(Manifest.permission.RECORD_AUDIO) == PackageManager.PERMISSION_GRANTED) {
            startVoiceCapture()
        } else {
            microphonePermission.launch(Manifest.permission.RECORD_AUDIO)
        }
    }

    private fun startVoiceCapture() {
        speechOutput.stop()
        refreshVoiceCapabilities()
        if (voice.inputMode == SpeechInputMode.UNAVAILABLE) {
            voice = voice.copy(
                sessionState = VoiceSessionState.ERROR,
                detail = "Na urządzeniu nie ma dostępnej usługi rozpoznawania mowy.",
            )
            return
        }

        voice = voice.copy(sessionState = VoiceSessionState.LISTENING, detail = "Uruchamianie mikrofonu…")
        speechInput.start { event ->
            when (event) {
                is VoiceInputEvent.Ready -> {
                    voice = voice.copy(
                        sessionState = VoiceSessionState.LISTENING,
                        inputMode = event.mode,
                        detail = if (event.mode == SpeechInputMode.ON_DEVICE) {
                            "Słucham · rozpoznawanie lokalne na urządzeniu."
                        } else {
                            "Słucham · systemowa usługa rozpoznawania; może korzystać z sieci."
                        },
                    )
                }

                is VoiceInputEvent.Partial -> {
                    input = event.transcript.text
                    voice = voice.copy(
                        sessionState = VoiceSessionState.LISTENING,
                        detail = "Rozpoznaję wypowiedź…",
                    )
                }

                is VoiceInputEvent.Final -> {
                    input = event.transcript.text
                    voice = voice.copy(
                        sessionState = VoiceSessionState.PROCESSING,
                        detail = "Polecenie rozpoznane. Security Engine wykonuje je przez Broker.",
                    )
                    executeMessage(event.transcript.text, speakReply = true)
                }

                is VoiceInputEvent.Error -> {
                    voice = voice.copy(
                        sessionState = VoiceSessionState.ERROR,
                        detail = "${event.code}: ${event.detail}",
                    )
                }
            }
        }
    }

    private fun executeMessage(message: String, speakReply: Boolean) {
        val boundedMessage = message.trim()
        if (boundedMessage.isBlank() || state is CopilotUiState.Working) return

        val plan = copilot.plan(
            userText = boundedMessage,
            context = CopilotContext(
                facts = emptyList(),
                allowedActions = runtime.supportedActions,
            ),
        )

        val command = plan.proposedCommand
        if (command == null) {
            val answer = CopilotUiState.Answer(
                explanation = plan.explanation,
                result = null,
                verification = null,
                warning = plan.warnings.joinToString().ifBlank { null },
            )
            state = answer
            voice = voice.copy(sessionState = VoiceSessionState.IDLE, detail = "Nie wykonano akcji Security Engine.")
            if (speakReply) speakInformational(plan.explanation)
            return
        }

        state = CopilotUiState.Working(plan.explanation)
        voice = voice.copy(sessionState = VoiceSessionState.PROCESSING, detail = "Weryfikuję wykonanie polecenia…")
        Thread {
            val result = runCatching { runtime.submit(command) }
            runOnUiThread {
                result.fold(
                    onSuccess = { brokerResult ->
                        state = brokerResult.toUiState(plan.explanation)
                        if (speakReply) {
                            speakBrokerResult(brokerResult, plan.explanation)
                        } else {
                            voice = voice.copy(sessionState = VoiceSessionState.IDLE, detail = "Polecenie zakończone.")
                        }
                    },
                    onFailure = { error ->
                        state = CopilotUiState.Answer(
                            explanation = plan.explanation,
                            result = "Polecenie nie zostało ukończone: ${error.message ?: error::class.java.simpleName}",
                            verification = "Brak pozytywnej weryfikacji.",
                            warning = "EXECUTION_FAILED",
                        )
                        voice = voice.copy(sessionState = VoiceSessionState.ERROR, detail = "Polecenie nie zostało ukończone.")
                        if (speakReply) {
                            speakInformational("Polecenie nie zostało ukończone i nie ma pozytywnej weryfikacji.")
                        }
                    },
                )
            }
        }.start()
    }

    private fun speakBrokerResult(result: BrokerResult, explanation: String) {
        val reply = when (result) {
            is BrokerResult.Completed -> SpokenReplyComposer.compose(
                explanation = explanation,
                result = result.execution.detail,
                verification = result.verification.detail,
                verified = result.verification.verified,
            )

            is BrokerResult.Denied -> SpokenReply(
                text = "Operacja została odrzucona. ${result.decision.reason}".take(SpokenReply.MAX_SPOKEN_CHARS),
                verified = false,
            )

            is BrokerResult.AwaitingHumanGate -> SpokenReply(
                text = "Operacja nie została wykonana. Wymagane jest potwierdzenie użytkownika. ${result.reason}".take(SpokenReply.MAX_SPOKEN_CHARS),
                verified = false,
            )
        }
        speakReply(reply)
    }

    private fun speakInformational(text: String) {
        val bounded = text.trim().take(SpokenReply.MAX_SPOKEN_CHARS)
        if (bounded.isBlank()) return
        speakReply(SpokenReply(bounded, verified = false))
    }

    private fun speakReply(reply: SpokenReply) {
        refreshVoiceCapabilities()
        val spoken = speechOutput.speak(reply)
        if (!spoken) {
            voice = voice.copy(
                sessionState = VoiceSessionState.IDLE,
                detail = when (voice.outputMode) {
                    SpeechOutputMode.SYSTEM_NETWORK -> "Odpowiedź tekstowa gotowa. TTS wymaga sieci i jest zablokowany przez politykę local-first."
                    SpeechOutputMode.UNAVAILABLE -> "Odpowiedź tekstowa gotowa. Brak dostępnego polskiego TTS."
                    else -> "Odpowiedź tekstowa gotowa. TTS nie jest jeszcze gotowy."
                },
            )
        }
    }

    private fun refreshVoiceCapabilities() {
        voice = voice.copy(
            inputMode = speechInput.mode(),
            outputMode = if (::speechOutput.isInitialized) speechOutput.mode() else SpeechOutputMode.UNAVAILABLE,
        )
    }
}

private data class VoiceUiState(
    val inputMode: SpeechInputMode = SpeechInputMode.UNAVAILABLE,
    val outputMode: SpeechOutputMode = SpeechOutputMode.UNAVAILABLE,
    val sessionState: VoiceSessionState = VoiceSessionState.IDLE,
    val detail: String? = null,
)

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
    voice: VoiceUiState,
    onInputChanged: (String) -> Unit,
    onSend: () -> Unit,
    onVoice: () -> Unit,
    onStopVoice: () -> Unit,
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
                    "Tekst lub głos → zamknięta SecurityAction → Policy Engine → capability check → executor → verifier → audit.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            item {
                VoiceCard(voice = voice, onVoice = onVoice, onStopVoice = onStopVoice)
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
                    label = { Text("Napisz lub podyktuj polecenie") },
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
private fun VoiceCard(
    voice: VoiceUiState,
    onVoice: () -> Unit,
    onStopVoice: () -> Unit,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(containerColor = Color.White),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text("Rozmowa głosowa", fontWeight = FontWeight.Bold)
            Text("STT: ${inputModeLabel(voice.inputMode)}")
            Text("TTS: ${outputModeLabel(voice.outputMode)}")
            voice.detail?.let { Text(it, style = MaterialTheme.typography.bodySmall) }

            if (voice.sessionState == VoiceSessionState.LISTENING ||
                voice.sessionState == VoiceSessionState.PROCESSING ||
                voice.sessionState == VoiceSessionState.SPEAKING
            ) {
                OutlinedButton(
                    modifier = Modifier.fillMaxWidth(),
                    onClick = onStopVoice,
                ) {
                    Text("ZATRZYMAJ GŁOS")
                }
            } else {
                Button(
                    modifier = Modifier.fillMaxWidth(),
                    enabled = voice.inputMode != SpeechInputMode.UNAVAILABLE,
                    onClick = onVoice,
                ) {
                    Text("MÓW")
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

private fun inputModeLabel(mode: SpeechInputMode): String = when (mode) {
    SpeechInputMode.ON_DEVICE -> "lokalny · on-device"
    SpeechInputMode.SYSTEM_SERVICE -> "systemowy · może używać sieci"
    SpeechInputMode.UNAVAILABLE -> "niedostępny"
}

private fun outputModeLabel(mode: SpeechOutputMode): String = when (mode) {
    SpeechOutputMode.ON_DEVICE -> "lokalny"
    SpeechOutputMode.SYSTEM_SERVICE -> "systemowy · tryb sieci nieustalony"
    SpeechOutputMode.SYSTEM_NETWORK -> "sieciowy · automatyczne użycie wyłączone"
    SpeechOutputMode.UNAVAILABLE -> "niedostępny / inicjalizacja"
}
