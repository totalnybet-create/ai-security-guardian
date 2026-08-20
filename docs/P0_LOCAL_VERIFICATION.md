# P0 Local Verification

GitHub-hosted Actions are currently unavailable because the account has exhausted its hosted-runner allowance. This does not invalidate the code; it blocks only that CI execution path.

Independent verification performed outside GitHub Actions:

- Kotlin core-security sources were reconstructed from the repository branch `work/p0-security-core`.
- Compiled with the local Kotlin compiler into an executable JAR.
- Executed deterministic P0 security tests without Gradle or Android SDK dependencies.

Verified scenarios:

1. Trusted ordinary application from Google Play -> risk score `0`, verdict `SAFE`.
2. Sideloaded application with active Accessibility + overlay + APK installation capability + microphone + camera -> risk score `100`, verdict `CRITICAL`.
3. FullScanService on a high-risk application -> high/critical count >= 1, security alert emitted, `APP_RISK_DETECTED` audit event emitted, `FULL_APP_SCAN_COMPLETED` audit event emitted.

Observed output:

`P0_CORE_TESTS_OK ordinary=0 critical=100 scanScore=0 audits=2 alerts=1`

Scope of this verification:

- VERIFIED: deterministic core models, RiskEngine logic, correlation rules, FullScanService orchestration, alert invocation contract, audit invocation contract.
- NOT YET VERIFIED BY ANDROID COMPILER: PackageManager integration, Android manifests/resources, notification implementation, Compose UI, APK assembly.

The Android-specific layer remains a separate verification gate and must not be described as production-verified until an Android SDK build succeeds.
