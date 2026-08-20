package pl.siedlar.securityguardian.voice.android

import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.os.Looper
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import pl.siedlar.securityguardian.voice.SpeechInputMode
import pl.siedlar.securityguardian.voice.VoiceInputEvent
import pl.siedlar.securityguardian.voice.VoiceTranscript

class AndroidSpeechInput(
    context: Context,
) {
    private val appContext = context.applicationContext
    private var recognizer: SpeechRecognizer? = null
    private var listener: ((VoiceInputEvent) -> Unit)? = null

    fun mode(): SpeechInputMode = when {
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
            SpeechRecognizer.isOnDeviceRecognitionAvailable(appContext) -> SpeechInputMode.ON_DEVICE
        SpeechRecognizer.isRecognitionAvailable(appContext) -> SpeechInputMode.SYSTEM_SERVICE
        else -> SpeechInputMode.UNAVAILABLE
    }

    fun start(
        languageTag: String = DEFAULT_LANGUAGE_TAG,
        onEvent: (VoiceInputEvent) -> Unit,
    ): Boolean {
        requireMainThread()
        val inputMode = mode()
        if (inputMode == SpeechInputMode.UNAVAILABLE) {
            onEvent(VoiceInputEvent.Error("STT_UNAVAILABLE", "Brak usługi rozpoznawania mowy na urządzeniu."))
            return false
        }

        destroyRecognizer()
        listener = onEvent

        val instance = runCatching {
            if (inputMode == SpeechInputMode.ON_DEVICE && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                SpeechRecognizer.createOnDeviceSpeechRecognizer(appContext)
            } else {
                SpeechRecognizer.createSpeechRecognizer(appContext)
            }
        }.getOrElse { error ->
            onEvent(VoiceInputEvent.Error("STT_CREATE_FAILED", error.message ?: error::class.java.simpleName))
            return false
        }

        recognizer = instance
        instance.setRecognitionListener(object : RecognitionListener {
            override fun onReadyForSpeech(params: Bundle?) {
                listener?.invoke(VoiceInputEvent.Ready(inputMode))
            }

            override fun onBeginningOfSpeech() = Unit
            override fun onRmsChanged(rmsdB: Float) = Unit
            override fun onBufferReceived(buffer: ByteArray?) = Unit
            override fun onEndOfSpeech() = Unit

            override fun onError(error: Int) {
                listener?.invoke(
                    VoiceInputEvent.Error(
                        code = errorCode(error),
                        detail = errorDetail(error),
                    ),
                )
            }

            override fun onResults(results: Bundle?) {
                extractTranscript(results, isFinal = true)?.let { transcript ->
                    listener?.invoke(VoiceInputEvent.Final(transcript))
                } ?: listener?.invoke(
                    VoiceInputEvent.Error("STT_EMPTY_RESULT", "Rozpoznawanie zakończyło się bez tekstu."),
                )
            }

            override fun onPartialResults(partialResults: Bundle?) {
                extractTranscript(partialResults, isFinal = false)?.let { transcript ->
                    listener?.invoke(VoiceInputEvent.Partial(transcript))
                }
            }

            override fun onEvent(eventType: Int, params: Bundle?) = Unit
        })

        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, languageTag)
            putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, true)
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 3)
            if (inputMode == SpeechInputMode.ON_DEVICE) {
                putExtra(RecognizerIntent.EXTRA_PREFER_OFFLINE, true)
            }
        }

        return runCatching {
            instance.startListening(intent)
            true
        }.getOrElse { error ->
            onEvent(VoiceInputEvent.Error("STT_START_FAILED", error.message ?: error::class.java.simpleName))
            destroyRecognizer()
            false
        }
    }

    fun cancel() {
        requireMainThread()
        runCatching { recognizer?.cancel() }
    }

    fun destroy() {
        requireMainThread()
        destroyRecognizer()
        listener = null
    }

    private fun destroyRecognizer() {
        runCatching { recognizer?.destroy() }
        recognizer = null
    }

    private fun extractTranscript(bundle: Bundle?, isFinal: Boolean): VoiceTranscript? {
        val candidates = bundle
            ?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
            .orEmpty()
        val text = candidates.firstOrNull()?.trim()?.take(VoiceTranscript.MAX_TRANSCRIPT_CHARS)
            ?.takeIf(String::isNotBlank)
            ?: return null
        val confidence = bundle
            ?.getFloatArray(SpeechRecognizer.CONFIDENCE_SCORES)
            ?.firstOrNull()
            ?.takeIf { it in 0f..1f }
        return VoiceTranscript(text = text, isFinal = isFinal, confidence = confidence)
    }

    private fun errorCode(error: Int): String = when (error) {
        SpeechRecognizer.ERROR_AUDIO -> "STT_AUDIO"
        SpeechRecognizer.ERROR_CLIENT -> "STT_CLIENT"
        SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS -> "STT_PERMISSION"
        SpeechRecognizer.ERROR_NETWORK -> "STT_NETWORK"
        SpeechRecognizer.ERROR_NETWORK_TIMEOUT -> "STT_NETWORK_TIMEOUT"
        SpeechRecognizer.ERROR_NO_MATCH -> "STT_NO_MATCH"
        SpeechRecognizer.ERROR_RECOGNIZER_BUSY -> "STT_BUSY"
        SpeechRecognizer.ERROR_SERVER -> "STT_SERVER"
        SpeechRecognizer.ERROR_SPEECH_TIMEOUT -> "STT_SPEECH_TIMEOUT"
        else -> "STT_ERROR_$error"
    }

    private fun errorDetail(error: Int): String = when (error) {
        SpeechRecognizer.ERROR_INSUFFICIENT_PERMISSIONS -> "Brak zgody na mikrofon."
        SpeechRecognizer.ERROR_NO_MATCH -> "Nie rozpoznano wypowiedzi."
        SpeechRecognizer.ERROR_SPEECH_TIMEOUT -> "Nie wykryto mowy."
        SpeechRecognizer.ERROR_RECOGNIZER_BUSY -> "Usługa rozpoznawania jest zajęta."
        SpeechRecognizer.ERROR_NETWORK, SpeechRecognizer.ERROR_NETWORK_TIMEOUT -> "Systemowa usługa rozpoznawania zgłosiła problem sieciowy."
        else -> "Rozpoznawanie mowy zakończyło się błędem $error."
    }

    private fun requireMainThread() {
        check(Looper.myLooper() == Looper.getMainLooper()) {
            "SpeechRecognizer must be controlled from the main thread"
        }
    }

    companion object {
        const val DEFAULT_LANGUAGE_TAG = "pl-PL"
    }
}
