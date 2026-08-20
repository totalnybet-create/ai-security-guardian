# P1 Privacy Guard — Local Verification

Independent verification performed outside GitHub Actions on 2026-08-20.

Environment:

- `kotlinc-jvm 1.9.0`
- OpenJDK 21
- pure Kotlin privacy engine compiled without Android SDK dependencies

Verification artifact SHA-256:

`c126306f7c740b08a866027d685647295b2e25a57028863ff61c929e78cb6ca9`

Observed output:

`P1_PRIVACY_TESTS_OK camera=3 risky=100 confidence=96 micState=UNKNOWN`

Verified scenarios:

1. Camera permission alone -> risk score `3`, verdict remains `SAFE`; P1 does not label ordinary permissions as malware.
2. Active Accessibility + overlay capability + enabled Notification Listener + microphone + camera -> risk score `100`, verdict `CRITICAL`, with correlation evidence.
3. When Android does not provide evidence that microphone/camera are actively in use, state remains `UNKNOWN`; the engine does not manufacture an `ACTIVE` observation.

Verified scope:

- privacy data model and observation-state semantics,
- deterministic PrivacyRiskEngine scoring,
- correlation rules,
- false-positive guard for ordinary camera permission,
- no hallucinated active microphone/camera state.

Still pending Android SDK build verification:

- `AndroidPrivacyInspector`,
- `NotificationManagerCompat.getEnabledListenerPackages()` integration,
- `PowerManager.isIgnoringBatteryOptimizations(packageName)` integration,
- final app wiring/UI.
