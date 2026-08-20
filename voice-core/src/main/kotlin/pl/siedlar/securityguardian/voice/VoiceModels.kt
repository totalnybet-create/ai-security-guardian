package pl.siedlar.securityguardian.voice

enum class SpeechInputMode {
    ON_DEVICE,
    SYSTEM_SERVICE,
    UNAVAILABLE,
}

enum class SpeechOutputMode {
    ON_DEVICE,
    SYSTEM_SERVICE,
    SYSTEM_NETWORK,
    UNAVAILABLE,
}

enum class VoiceSessionState {
    IDLE,
    LISTENING,
    PROCESSING,
    SPEAKING,
    ERROR,
}

data class VoiceCapabilities(
    val inputMode: SpeechInputMode,
    val outputMode: SpeechOutputMode,
    val languageTag: String,
)

data class VoiceTranscript(
    val text: String,
    val isFinal: Boolean,
    val confidence: Float? = null,
) {
    init {
        require(text.length <= MAX_TRANSCRIPT_CHARS)
        confidence?.let { require(it in 0f..1f) }
    }

    companion object {
        const val MAX_TRANSCRIPT_CHARS = 8_192
    }
}

sealed interface VoiceInputEvent {
    data class Ready(val mode: SpeechInputMode) : VoiceInputEvent
    data class Partial(val transcript: VoiceTranscript) : VoiceInputEvent
    data class Final(val transcript: VoiceTranscript) : VoiceInputEvent
    data class Error(val code: String, val detail: String) : VoiceInputEvent
}

data class SpokenReply(
    val text: String,
    val verified: Boolean,
) {
    init {
        require(text.isNotBlank())
        require(text.length <= MAX_SPOKEN_CHARS)
    }

    companion object {
        const val MAX_SPOKEN_CHARS = 2_000
    }
}

object SpokenReplyComposer {
    fun compose(
        explanation: String,
        result: String?,
        verification: String?,
        verified: Boolean,
    ): SpokenReply {
        val parts = buildList {
            explanation.trim().takeIf(String::isNotBlank)?.let(::add)
            result?.trim()?.takeIf(String::isNotBlank)?.let(::add)
            verification?.trim()?.takeIf(String::isNotBlank)?.let(::add)
            if (!verified) add("Wynik nie ma pozytywnej weryfikacji.")
        }
        val bounded = parts.joinToString(" ")
            .replace(Regex("\\s+"), " ")
            .take(SpokenReply.MAX_SPOKEN_CHARS)
            .trim()
            .ifBlank { "Nie uzyskano zweryfikowanego wyniku." }
        return SpokenReply(bounded, verified)
    }
}
