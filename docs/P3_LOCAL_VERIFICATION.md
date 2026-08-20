# P3 Network Guard — Local Verification

Independent verification performed outside GitHub Actions on 2026-08-20.

Environment:

- `kotlinc-jvm 1.9.0`
- OpenJDK 21
- pure Kotlin `network-core`, no Android SDK dependency

Verification artifacts SHA-256:

- Policy/threat-intelligence regression: `483128e4c5e9848be4cf9f10a7adcc5f11d9a3e51ec74297d74e401652985e7b`
- IPv4/IPv6 + DNS parser regression: `0f22fe5395d0f83b1185416f41486029723d2c24d3ed0c858ea0bad658c7da84`
- DNS block response round-trip: `157ea677d1db83cddffabc20e54817e23791cca53218d2a2450d438a17239b45`

Observed outputs:

`P3_NETWORK_POLICY_TESTS_OK provider=UNKNOWN malicious=BLOCK temp=TEMPORARY_ALLOW lookalike=ALLOW idn=BLOCK suspicious=ASK`

`P3_PACKET_DNS_TESTS_OK status=PARSED host=example.com loopBlocked=true`

`P3_DNS_ENFORCEMENT_TEST_OK host=blocked.example rcode=3 bytes=61`

Verified scenarios:

1. Optional threat-intelligence provider failure becomes `UNKNOWN` evidence and fails open to `ALLOW` instead of breaking normal connectivity.
2. High-confidence `MALICIOUS` threat evidence produces `BLOCK`, even when an ordinary ALLOW rule matches.
3. Explicit BLOCK rules take precedence over ordinary ALLOW/TEMPORARY_ALLOW/ASK rules.
4. `TEMPORARY_ALLOW` is active only before its exact expiry timestamp and automatically disappears at expiry.
5. Domain-suffix matching blocks `api.example.com` for `example.com` but does not falsely match `evil-example.com`.
6. Domain matching canonicalizes case, trailing dots and IDN/punycode using Java IDN STD3 rules.
7. `SUSPICIOUS` evidence produces `ASK`, not silent blocking.
8. Bounded IPv4/IPv6 parsing validates header lengths, transport offsets, UDP lengths, TCP data offsets and IPv6 extension-header limits.
9. Non-initial IP fragments never invent TCP/UDP ports; fragmented DNS is excluded from DNS classification/enforcement.
10. DNS parsing limits question count, label/wire lengths and compression-pointer depth, and rejects pointer loops.
11. Local DNS block enforcement creates an `NXDOMAIN` payload and a checksum-valid IPv4/UDP response with source/destination IP and ports reversed back to the client.
12. The generated DNS response reparses as a DNS response with transaction/question metadata preserved and `RCODE=3`.
13. `SERVFAIL` is available as an explicit non-block fallback for upstream/overload failures.

Verified pure-Kotlin scope:

- network flow/rule/evidence/decision models,
- deterministic rule matching and expiry semantics,
- IDN/punycode domain canonicalization,
- explicit-block / malicious-reputation precedence,
- suspicious `ASK` behavior,
- provider failure isolation and optional-provider fail-open behavior,
- bounded IPv4/IPv6/TCP/UDP metadata parsing,
- bounded DNS question parsing and compression-loop defense,
- packet-to-flow extraction,
- local DNS error response generation,
- IPv4/IPv6 UDP response construction and checksum logic.

Android implementation added in this checkpoint but still awaiting Android SDK compiler/device verification:

- `network-guard` Android library,
- user-consent flow through `VpnService.prepare()`,
- foreground `GuardianDnsVpnService`,
- DNS-only TUN configuration that routes only the virtual DNS `/32`, not all Internet traffic,
- persistent manual domain BLOCK rules,
- connection-owner attribution when Android can return an unambiguous UID/package,
- upstream DNS forwarding through Android `DnsResolver.rawQuery()` on a non-VPN underlying network,
- local `NXDOMAIN` block enforcement and `SERVFAIL` failure behavior,
- bounded DNS worker queue with overload `SERVFAIL`,
- privacy-minimized audit policy: ordinary successful DNS resolutions are not persisted,
- live in-process guard state so a stale persisted `RUNNING` state cannot survive process death,
- light Network Guard control screen and dashboard entry.

Important invariants:

- Provider failure alone never blocks networking.
- `UNKNOWN != MALICIOUS`.
- A lookalike domain is not treated as a subdomain match.
- Unknown/ambiguous flow ownership remains unknown; Guardian does not invent an app owner.
- Ordinary successful DNS lookups are not persisted to the audit log.
- The current Android transport is **DNS-only**. It must not be described as a full TCP/UDP firewall.
- The Android-only implementation must not be described as production-verified until Android SDK build, emulator and real-device tests pass.

Still pending:

- Android SDK/APK build verification for the P3 Android path,
- emulator and real-device DNS enforcement tests,
- remote/local threat-intelligence provider integration into the running DNS service,
- interactive notification/UI completion for future `ASK` decisions,
- full TCP/UDP forwarding/firewall path,
- DoH/custom-tunnel visibility strategy and explicit limitations,
- battery/performance and network-change regression,
- production Google Play foreground-service/VPN policy review.
