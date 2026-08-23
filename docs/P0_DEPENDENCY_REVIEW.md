# P0 Dependency Review — 2026-08-20

Verified against current upstream release documentation before continuing implementation:

- Android Gradle Plugin: `8.13.2` — released and in active use.
- Kotlin Gradle plugins: `2.3.21` — released stable version.
- Jetpack Compose BOM: `2026.06.01` — current documented BOM in Android Compose setup guidance.
- AndroidX Activity Compose: upgraded from `1.12.4` to current stable `1.13.0`.
- compileSdk / targetSdk: Android API 36.

No preview/beta dependency is intentionally required by P0.
