package pl.siedlar.securityguardian.voice.android

import android.content.Context
import android.os.Bundle
import android.speech.tts.TextToSpeech
import android.speech.tts.UtteranceProgressListener
import android.speech.tts.Voice
import pl.siedlar.securityguardian.voice.SpeechOutputMode
import pl.siedlar.securityguardian.voice.SpokenReply
import pl.siedlar.securityguardian.voice.VoiceSessionState
import java.util.Locale
import java.util.UUID

class AndroidSpeechOutput(
    context: Context,
    private val allowNetworkFallback: Boolean = false,
    private val languageTag: String = DEFAULT_LANGUAGE_TAG,
    private val onState: (VoiceSessionState) -> Unit = {},
) {
    private val appContext = context.applicationContext
    @Volatile private var ready = false
    @Volatile private var outputMode = SpeechOutputMode.UNAVAILABLE
    private var selectedVoice: Voice? = null
    private var tts: TextToSpeech? = null

    init {
        tts = TextToSpeech(appContext) { status ->
            if (status != TextToSpeech.SUCCESS) {
                ready = false
                outputMode = SpeechOutputMode.UNAVAILABLE
                onState(VoiceSessionState.ERROR)
                return@TextToSpeech
            }
            configureVoice()
        }.also { engine ->
            engine.setOnUtteranceProgressListener(object : UtteranceProgressListener() {
                override fun onStart(utteranceId: String?) {
                    onState(VoiceSessionState.SPEAKING)
                }

                override fun onDone(utteranceId: String?) {
                    onState(VoiceSessionState.IDLE)
                }

                @Deprecated("Deprecated by platform callback shape")
                override fun onError(utteranceId: String?) {
                    onState(VoiceSessionState.ERROR)
                }

                override fun onError(utteranceId: String?, errorCode: Int) {
                    onState(VoiceSessionState.ERROR)
                }
            })
        }
    }

    fun mode(): SpeechOutputMode = outputMode

    fun isReady(): Boolean = ready

    fun speak(reply: SpokenReply): Boolean {
        val engine = tts ?: return false
        if (!ready) return false
        if (!allowNetworkFallback &&
            (outputMode == SpeechOutputMode.SYSTEM_NETWORK || outputMode == SpeechOutputMode.SYSTEM_SERVICE)
        ) {
            return false
        }

        val utteranceId = "guardian-${UUID.randomUUID()}"
        val params = Bundle().apply {
            putFloat(TextToSpeech.Engine.KEY_PARAM_VOLUME, 1.0f)
        }
        val result = engine.speak(
            reply.text,
            TextToSpeech.QUEUE_FLUSH,
            params,
            utteranceId,
        )
        return result == TextToSpeech.SUCCESS
    }

    fun stop() {
        runCatching { tts?.stop() }
        onState(VoiceSessionState.IDLE)
    }

    fun shutdown() {
        ready = false
        runCatching { tts?.stop() }
        runCatching { tts?.shutdown() }
        tts = null
        selectedVoice = null
        outputMode = SpeechOutputMode.UNAVAILABLE
    }

    private fun configureVoice() {
        val engine = tts ?: return
        val locale = Locale.forLanguageTag(languageTag)
        val polishVoices = engine.voices.orEmpty()
            .asSequence()
            .filter { voice -> voice.locale.language.equals(locale.language, ignoreCase = true) }
            .filterNot { voice -> voice.features.contains(TextToSpeech.Engine.KEY_FEATURE_NOT_INSTALLED) }
            .sortedWith(
                compareByDescending<Voice> { it.locale.country.equals(locale.country, ignoreCase = true) }
                    .thenByDescending { !it.isNetworkConnectionRequired }
                    .thenByDescending { it.quality }
                    .thenBy { it.latency }
                    .thenBy { it.name },
            )
            .toList()

        val localVoice = polishVoices.firstOrNull { !it.isNetworkConnectionRequired }
        val anyPolishVoice = polishVoices.firstOrNull()
        selectedVoice = localVoice ?: anyPolishVoice

        val configured = when (val voice = selectedVoice) {
            null -> {
                val availability = engine.isLanguageAvailable(locale)
                if (availability >= TextToSpeech.LANG_AVAILABLE) {
                    engine.setLanguage(locale) >= TextToSpeech.LANG_AVAILABLE
                } else {
                    false
                }
            }

            else -> engine.setVoice(voice) == TextToSpeech.SUCCESS
        }

        if (!configured) {
            ready = false
            outputMode = SpeechOutputMode.UNAVAILABLE
            onState(VoiceSessionState.ERROR)
            return
        }

        outputMode = when (val voice = selectedVoice) {
            null -> SpeechOutputMode.SYSTEM_SERVICE
            else -> if (voice.isNetworkConnectionRequired) {
                SpeechOutputMode.SYSTEM_NETWORK
            } else {
                SpeechOutputMode.ON_DEVICE
            }
        }
        ready = true
        onState(VoiceSessionState.IDLE)
    }

    companion object {
        const val DEFAULT_LANGUAGE_TAG = "pl-PL"
    }
}
