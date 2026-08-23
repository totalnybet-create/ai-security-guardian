# P0 Checkpoint

Implemented in this branch:
- repository threat model,
- Android privilege capability matrix,
- production architecture baseline,
- pure Kotlin risk engine with correlation and confidence,
- deterministic unit tests,
- real Android installed-app inventory,
- installer source, signing certificate SHA-256 and APK SHA-256 collection,
- requested/granted permission inspection,
- enabled Accessibility service detection,
- active Device Admin detection,
- app-private JSONL audit log,
- real Android HIGH/CRITICAL notifications,
- light Jetpack Compose dashboard,
- non-blocking full P0 scan,
- CI gate for unit tests and debug APK build.

Not yet claimed as implemented:
- whole-device privacy score,
- Play Integrity/Knox attestation,
- file/APK static malware engine,
- quarantine,
- VpnService firewall,
- phishing/reputation providers,
- AI Copilot and voice,
- Device Owner containment/removal.

The UI must not present any item in the second list as active protection until its implementation and verification land in a later checkpoint.
