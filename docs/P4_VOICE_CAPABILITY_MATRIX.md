# P4 Voice — Android Capability Matrix

## STANDARD app

### Microphone input — AVAILABLE WITH RUNTIME PERMISSION

Guardian requests `android.permission.RECORD_AUDIO` only when the user explicitly starts a voice interaction. This checkpoint does not run a persistent microphone service, hotword listener or background capture.

### On-device speech recognition — CONDITIONAL

On Android API 31+ Guardian checks `SpeechRecognizer.isOnDeviceRecognitionAvailable(context)` before creating an on-device recognizer. Only a positive platform capability result may be labelled `ON_DEVICE`.

If on-device recognition is unavailable but Android exposes a normal recognition service, Guardian may use the system recognizer. That path is labelled `SYSTEM_SERVICE` because it may use the network depending on the installed recognizer and system configuration.

### Text-to-speech — CONDITIONAL

Guardian enumerates Polish TTS voices and prefers an installed voice for `pl-PL` that does not require a network connection. Such a voice is labelled `ON_DEVICE`.

If the engine exposes only a network-dependent Polish voice, it is labelled `SYSTEM_NETWORK`. Automatic network TTS fallback is disabled in this checkpoint. If the engine cannot expose voice-level network metadata and only locale-level synthesis works, the path is labelled `SYSTEM_SERVICE` and is also blocked from automatic speech by the local-first policy.

Android's standard `Voice` metadata does not provide a reliable cross-engine gender field, therefore Guardian does not claim that a selected voice is female/male unless a future provider exposes trustworthy structured metadata.

### Command execution boundary

Voice recognition produces bounded text only. The text is passed to the same `GroundedCopilot` and closed `SecurityAction` catalog used by typed commands. STT cannot invoke an executor directly.

The execution path remains:

`VOICE -> STT -> INTENT -> POLICY -> CAPABILITY -> HUMAN GATE -> EXECUTOR -> VERIFIER -> AUDIT -> TTS`

A destructive/irreversible command keeps its normal Human Gate regardless of whether it originated from voice or text.

## DEVICE OWNER / ROOT

No additional voice privilege is required or granted for Device Owner/root editions. Elevated Android privileges must not broaden the LLM/voice command vocabulary outside the closed SecurityAction + Policy Engine model.

## Mandatory production gates

1. Android SDK compile and APK build.
2. API 29-36 microphone-permission regression where supported by the application's min SDK/runtime behavior.
3. API 31+ on-device recognizer availability tests.
4. Device tests with recognizer unavailable, on-device available and system-only available.
5. Polish TTS local/network/unavailable tests.
6. Speech recognizer `destroy()` and TTS `shutdown()` lifecycle verification.
7. Silence/end-of-speech, cancellation and repeated-session tests.
8. Headset/Bluetooth/audio-focus tests.
9. Voice-originated destructive Human Gate tests.
10. Privacy review confirming no hidden background listening or automatic network TTS fallback.
