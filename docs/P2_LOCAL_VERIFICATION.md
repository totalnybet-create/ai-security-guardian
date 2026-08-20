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
- Android `PackageManager.getPackageArchiveInfo()` APK archive inspection using a bounded private temporary copy,
- APK package/version/requested-permission/signing-certificate evidence,
- declared Accessibility/overlay/install-packages/Notification Listener/VPN capability extraction from PackageManager-visible archive data,
- light file-scan result screen,
- real Android HIGH/CRITICAL malware notification sink,
- `quarantine` Android module with verified private-vault copy, SHA-256 re-verification, `CONTAINED` / `VAULT_COPY_ONLY` / `FAILED` outcomes, restore verification, and persistent incident metadata,
- explicit Human Gate before original-document deletion,
- `install-guard` Android module with process-level package broadcasts and process-start reconciliation,
- lightweight install baseline (`packageName + lastUpdateTime`) so unchanged packages are not fully rehashed on every process start,
- duplicate update suppression for `PACKAGE_ADDED(EXTRA_REPLACING=true)` followed by `PACKAGE_REPLACED`,
- process-wide audit-file write serialization across multiple logger instances.

Static review performed after these additions:

- no stale `expectedSha256` quarantine call sites remain in PR #3,
- no `TODO` placeholders were found in the PR diff,
- quarantine destructive removal is gated by explicit confirmation,
- Android package-install monitoring does not use a false manifest receiver for package broadcasts restricted by Android 8+ background rules,
- APK `BOOT_COMPLETED` receiver declaration is not claimed from `PackageManager` archive parsing because intent-filter actions are not exposed by that path.

Important invariants:

- `UNKNOWN != MALICIOUS`. Lack of reputation data alone never produces a malware verdict.
- Bounded heuristic scanning is not described as full APK manifest analysis.
- `DELETE` is never selected automatically by the current malware risk engine.
- An unknown file size remains `null`; the implementation does not convert unknown to fake `0` bytes.
- `CONTAINED` is emitted only after a hash-verified vault copy exists and the original document was actually deleted.
- A verified vault copy without original deletion is `VAULT_COPY_ONLY`, never containment.
- Standard Install Guard does not claim guaranteed instant 24/7 observation after Android has killed the Guardian process; reconciliation closes the evidence gap on next process start.

Build infrastructure status:

- GitHub-hosted Actions remain unavailable because the account hosted-runner allowance is exhausted.
- The local execution container has OpenJDK 21 and `kotlinc-jvm 1.9.0` but no Android SDK, Gradle distribution, Android dependency cache, or outbound DNS required to download them.
- Google currently publishes a no-root Android CLI installer for Linux, but this execution environment cannot retrieve the required binary artifacts.
- Therefore Android-only code in this checkpoint is **implemented and statically reviewed, not Android-SDK-build-verified**.

Still pending before P2 can be called production-verified:

- Android SDK/APK build verification for all Android modules,
- emulator/device installation and regression tests,
- full binary AndroidManifest intent-filter parsing if boot-receiver evidence is required,
- concrete external reputation provider integrations or a signed local threat-intelligence feed,
- restore UI flow using a user-selected writable destination,
- full dashboard integration of malware/quarantine/install-guard state.
