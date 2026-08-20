# P2 Malware Core — Local Verification

Independent verification performed outside GitHub Actions on 2026-08-20.

Environment:

- `kotlinc-jvm 1.9.0`
- OpenJDK 21
- pure Kotlin malware core compiled without Android SDK dependencies

Verification artifacts:

- Malware risk/pipeline tests SHA-256: `a539f6a8d549301ac709cb99a5cd990cd660269ec24d18bbed58c585b187d41f`
- Local artifact preprocessor tests SHA-256: `84843543a30e713acf43b11d00799e567283380aa65c57e9e3cb09cdfa919b52`
- Unbounded-stream protection test SHA-256: `16dafd959c66357a3fb8db10860c689d7c3d79fcd7eca1b68a31fa04b3b64b12`

Observed outputs:

`P2_MALWARE_TESTS_OK unknown=0 known=100 correlated=100 provider=UNKNOWN audits=1`

`P2_PREPROCESSOR_TESTS_OK sha=baca97c35f4f dynamic=true native=1 truncated=true`

`P2_STREAM_LIMIT_TEST_OK blocked=true`

Verified scenarios:

1. Unknown document with no suspicious static evidence -> score `0`, verdict `SAFE`, disposition `ALLOW`. Unknown reputation is not treated as malware.
2. High-confidence known malicious hash -> score `100`, verdict `CRITICAL`, recommended disposition `QUARANTINE`.
3. Untrusted APK with dynamic code loading + Accessibility + overlay + install-package capability + boot persistence + heavy obfuscation -> score `100`, verdict `CRITICAL`, recommended disposition `QUARANTINE`.
4. Reputation provider failure -> provider result degrades to `UNKNOWN`; scan completes, does not generate a false malware alert, and writes `MALWARE_SCAN_COMPLETED` to audit.
5. Local preprocessor computes a real SHA-256 over artifact content and classifies APK/archive/document/image without a cloud provider.
6. APK/ZIP inspection detects bounded static indicators for dynamic class loading, shell/root strings, and native `.so` libraries.
7. A deceptive filename such as `invoice.pdf.apk` and a conflicting MIME type are detected.
8. Archive/byte scan limits produce `analysisTruncated=true` instead of pretending the whole artifact was inspected.
9. The bounded local preprocessor intentionally does not mark Accessibility/overlay/install-package/boot capabilities as declared without a proper Android binary-manifest parser.
10. Unknown-size/unbounded input cannot bypass the configured maximum artifact size; hashing stops with `ArtifactTooLargeException` instead of hanging or producing a partial SHA-256.

Verified scope:

- artifact/reputation/evidence models,
- provider abstraction and provider-failure isolation,
- deterministic malware risk scoring,
- correlation rules,
- `ALLOW/WATCH/BLOCK/QUARANTINE` decision semantics,
- prepared-artifact and static-analyzer scan orchestration,
- alert/audit contracts,
- streaming SHA-256 with hard maximum input size,
- bounded local content/archive scan,
- double-extension and MIME mismatch detection,
- native-library counting,
- explicit incomplete-analysis state.

Android implementation added but still awaiting Android SDK compiler/device verification:

- `file-scanner` Android library,
- `ContentResolver`/SAF `content://` acquisition with nullable size metadata,
- share-sheet `ACTION_SEND` entry point,
- local-only file scan controller,
- light file-scan result screen,
- real Android HIGH/CRITICAL malware notification sink.

Important invariants:

- `UNKNOWN != MALICIOUS`. Lack of reputation data alone never produces a malware verdict.
- Bounded heuristic scanning is not described as full APK manifest analysis.
- `DELETE` is never selected automatically by the current malware risk engine.
- An unknown file size remains `null`; the implementation does not convert unknown to fake `0` bytes.

Still pending:

- Android SDK/APK build verification for the Android file path,
- APK binary manifest/resource parser integration,
- concrete reputation provider integrations,
- quarantine storage implementation,
- full dashboard integration and real-device regression tests.
