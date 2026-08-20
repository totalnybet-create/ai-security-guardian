# P2 Malware Core — Local Verification

Independent verification performed outside GitHub Actions on 2026-08-20.

Environment:

- `kotlinc-jvm 1.9.0`
- OpenJDK 21
- pure Kotlin malware core compiled without Android SDK dependencies

Verification artifact SHA-256:

`a539f6a8d549301ac709cb99a5cd990cd660269ec24d18bbed58c585b187d41f`

Observed output:

`P2_MALWARE_TESTS_OK unknown=0 known=100 correlated=100 provider=UNKNOWN audits=1`

Verified scenarios:

1. Unknown document with no suspicious static evidence -> score `0`, verdict `SAFE`, disposition `ALLOW`. Unknown reputation is not treated as malware.
2. High-confidence known malicious hash -> score `100`, verdict `CRITICAL`, recommended disposition `QUARANTINE`.
3. Untrusted APK with dynamic code loading + Accessibility + overlay + install-package capability + boot persistence + heavy obfuscation -> score `100`, verdict `CRITICAL`, recommended disposition `QUARANTINE`.
4. Reputation provider failure -> provider result degrades to `UNKNOWN`; scan completes, does not generate a false malware alert, and writes `MALWARE_SCAN_COMPLETED` to audit.

Verified scope:

- artifact/reputation/evidence models,
- provider abstraction and provider-failure isolation,
- deterministic malware risk scoring,
- correlation rules,
- `ALLOW/WATCH/BLOCK/QUARANTINE` decision semantics,
- `MalwareScanService` orchestration,
- alert/audit contracts.

Important invariant:

`UNKNOWN != MALICIOUS`. Lack of reputation data alone never produces a malware verdict.

Still pending:

- actual Android file/content acquisition,
- APK binary manifest/resource parsing,
- concrete reputation provider integrations,
- quarantine storage implementation,
- Android notifications/UI integration,
- Android SDK/APK build verification.
