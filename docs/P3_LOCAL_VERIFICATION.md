# P3 Network Guard — Local Verification

Independent verification performed outside GitHub Actions on 2026-08-20.

Environment:

- `kotlinc-jvm 1.9.0`
- OpenJDK 21
- pure Kotlin `network-core`, no Android SDK dependency

Verification artifact SHA-256:

`483128e4c5e9848be4cf9f10a7adcc5f11d9a3e51ec74297d74e401652985e7b`

Observed output:

`P3_NETWORK_POLICY_TESTS_OK provider=UNKNOWN malicious=BLOCK temp=TEMPORARY_ALLOW lookalike=ALLOW idn=BLOCK suspicious=ASK`

Verified scenarios:

1. Optional threat-intelligence provider failure becomes `UNKNOWN` evidence and fails open to `ALLOW` instead of breaking normal connectivity.
2. High-confidence `MALICIOUS` threat evidence produces `BLOCK`, even when an ordinary ALLOW rule matches.
3. Explicit BLOCK rules take precedence over ordinary ALLOW/TEMPORARY_ALLOW/ASK rules.
4. `TEMPORARY_ALLOW` is active only before its exact expiry timestamp and automatically disappears at expiry.
5. Domain-suffix matching blocks `api.example.com` for `example.com` but does not falsely match `evil-example.com`.
6. Domain matching canonicalizes case, trailing dots and IDN/punycode using Java IDN STD3 rules.
7. `SUSPICIOUS` evidence produces `ASK`, not silent blocking.

Verified scope:

- network flow/rule/evidence/decision models,
- deterministic rule matching,
- rule expiry semantics,
- domain canonicalization,
- explicit block precedence,
- high-confidence malicious reputation handling,
- suspicious ASK behavior,
- provider failure isolation,
- fail-open behavior for optional unavailable reputation.

Important invariants:

- Provider failure alone never blocks networking.
- `UNKNOWN != MALICIOUS`.
- A lookalike domain is not treated as a subdomain match.
- No UI may claim that a firewall is active until the Android VpnService packet path is established, forwarding is functional, and enforcement is verified.

Still pending:

- Android `VpnService` adapter and user-consent flow,
- foreground-service lifecycle,
- packet parsing/forwarding engine,
- actual ALLOW/BLOCK enforcement against TUN traffic,
- DNS/domain extraction and network-event attribution,
- persistent rule storage and temporary-rule cleanup integration,
- Android notifications/UI,
- Android SDK build, emulator and real-device tests.
