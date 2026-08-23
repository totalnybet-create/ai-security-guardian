# P4 Voice — Local Verification

Independent pure-Kotlin verification performed outside GitHub Actions on 2026-08-20.

Environment:

- `kotlinc-jvm 1.9.0`
- OpenJDK 21
- pure Kotlin `voice-core`, no Android SDK dependency

Verification artifact SHA-256:

`d659d1133285d65c8e97ec4518b9d5d6bc21568479090950da79058b7d432d87`

Observed output:

`P4_VOICE_CORE_TEST_OK unverified=false bounded=2000 confidenceBlocked=true`

Verified pure-Kotlin scenarios:

1. An unverified security result remains explicitly marked `verified=false`.
2. Spoken responses are bounded to 2,000 characters.
3. Invalid STT confidence outside `0.0..1.0` is rejected.
4. The spoken reply composer appends a clear statement when a security result lacks positive verification.

Android implementation added but still awaiting Android SDK/device verification:

- runtime `RECORD_AUDIO` permission flow,
- on-device STT detection on API 31+,
- explicit fallback to the system speech-recognition service when on-device STT is unavailable,
- partial and final Polish transcript handling,
- final transcript automatically reusing the existing Grounded Copilot -> Command Broker -> Executor -> Verifier path,
- Polish TTS voice selection,
- preference for a non-network Polish TTS voice,
- network/unknown TTS automatic fallback disabled by default,
- automatic spoken response only after the command result is available,
- resource cleanup through `SpeechRecognizer.destroy()` and `TextToSpeech.shutdown()`.

No-fake/privacy invariants:

- `ON_DEVICE` is reported only when Android says on-device recognition is available.
- The normal system recognizer is labelled as potentially network-backed.
- The Guardian does not claim voice gender because Android's standard `Voice` model does not expose a reliable gender field.
- There is no hotword, always-listening microphone or background voice capture in this checkpoint.
- Speech-to-text never invokes Android security actions directly; it only produces text for the existing closed SecurityAction pipeline.
- If only a network-dependent TTS voice is available, automatic speech output is blocked by the local-first policy and the result remains visible as text.

Still pending:

- Android SDK/APK compilation,
- microphone permission regression on supported Android versions,
- on-device STT availability/device-language tests,
- system recognizer network/offline behavior tests,
- Polish TTS voice availability and lifecycle tests,
- real-device silence/end-of-speech behavior,
- Bluetooth/headset/audio-focus regression,
- accessibility and privacy review of voice UI.
