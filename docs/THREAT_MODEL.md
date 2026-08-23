# AI Security Guardian — Repository Threat Model

## Scope
Android mobile security platform with optional backend, AI provider adapters, threat-intelligence providers and enterprise/device-owner adapters.

## Primary assets
- device integrity and user control of the phone,
- credentials, sessions, passkeys and security tokens,
- microphone/camera/location privacy,
- messages, notifications, contacts and local files,
- installed-app inventory and security telemetry,
- quarantine contents and forensic/audit records,
- backend credentials and provider API keys,
- policy engine and privileged action channel.

## Adversaries
- commodity malware, spyware, stalkerware, RATs, droppers and ransomware,
- phishing/smishing operators and malicious websites,
- malicious/supply-chain-compromised apps and updates,
- local attacker with temporary physical access,
- hostile Wi-Fi/network operator and DNS/MITM actor,
- attacker abusing Accessibility, overlays, notification listeners, VPN or Device Admin,
- attacker with ADB/debug access,
- attacker attempting to compromise Security Guardian itself,
- advanced attacker exploiting kernel/firmware/baseband zero-days.

## Trust boundaries
1. Android sandbox and OS APIs.
2. Security Guardian app process and app-private storage.
3. Device Owner / Android Enterprise APIs when provisioned.
4. Optional Samsung Knox enterprise APIs.
5. Optional ADB/Shizuku privileged adapter.
6. Optional root adapter; never trusted by the core as a prerequisite.
7. Local VPN packet boundary.
8. Security backend and provider proxy.
9. Threat-intelligence/reputation providers.
10. AI provider boundary.
11. User confirmation / biometric Human Gate.

## Attacker-controlled inputs
- APKs, files, archives, documents and shared content,
- URLs, QR payloads, redirects and deep links,
- app metadata, manifests, labels, package names and certificates,
- DNS names, IP addresses and network traffic,
- notification text made available to the product,
- external provider responses,
- AI prompts derived from untrusted device/security data.

## Security invariants
- AI never directly executes shell/system commands.
- Evidence is structured and separated from natural-language explanation.
- Untrusted strings never become executable policy.
- Destructive actions require Human Gate and post-action verification.
- A provider outage cannot silently disable core local protection.
- Unknown/failed integrity is never represented as trusted.
- Audit records must describe action, result and verification.
- The product must never require users to weaken Android security to enable the normal edition.

## Threat coverage map
| Threat | Detect | Score | Explain | Contain | Remove | Verify |
|---|---|---|---|---|---|---|
| Sideloaded/suspicious app | package inventory, installer, cert/hash, permissions | correlated app risk | evidence list | Device Owner suspend / VPN block where available | uninstall flow / enterprise action | rescan inventory |
| Accessibility abuse | enabled accessibility services + app capabilities | high correlation weight | active service + associated capabilities | enterprise suspend/revoke where possible | uninstall/disable with user or admin flow | service no longer enabled |
| Overlay abuse | declared overlay capability + correlations; active state only where API allows | correlation | capability and limitation | policy/enterprise action | uninstall/revoke via settings/admin | rescan |
| Notification listener abuse | service capability; active state when supported | correlation | capability/evidence | admin/user settings action | uninstall/revoke | rescan |
| Device Admin abuse | active admin inventory | high | active admin evidence | Device Owner policy / guided removal | remove admin then uninstall | active-admin rescan |
| Spyware mic/camera capability | permissions + control/persistence correlations | contextual | why combination matters | revoke/suspend when capability permits | uninstall | permission/app rescan |
| Malicious APK/file | hash/static/reputation engines (P2) | multi-engine | signatures/heuristics | quarantine | delete after confirmation | hash/path rescan |
| Phishing URL | reputation/redirect/punycode rules (P3) | URL risk | reasons | block/open isolated | n/a | re-evaluate final URL |
| C2/network anomaly | VPN/DNS/IOC and enterprise network logs (P3) | behavioral | app/domain evidence | VPN block | remove responsible app | traffic stops |
| Root/boot compromise | Play Integrity / Knox attestation where supported (P1/P5) | critical trust failure | integrity verdict | isolate sensitive functions | trusted recovery workflow | fresh attestation |
| ADB/debug exposure | settings/device policy checks | configuration risk | exact setting | enterprise policy / guided fix | disable | recheck |
| Rogue Bluetooth | bonded-device and permission checks; Knox allowlist in enterprise | contextual | known/unknown device | enterprise/Knox policy | unpair/block | bonded-device recheck |
| Kernel/baseband zero-day | partial indicators/attestation only | trust uncertainty | explicit limitation | isolate device/network | clean recovery/firmware path | independent attestation + clean baseline |

## Highest-impact repository failure modes
- LLM or untrusted content reaches privileged executor without policy/human gate.
- False "safe" result because unavailable Android telemetry was interpreted as clean.
- Security score is fabricated or not traceable to evidence.
- Quarantine/delete UI reports success without verifying storage state.
- Firewall failure blocks all networking or silently stops filtering.
- App collects sensitive telemetry beyond the declared security purpose.
- Backend/provider secret is embedded in mobile binaries.
- Security Guardian exported components permit unauthorized privileged actions.

## Out of scope guarantees
No Android app can guarantee detection of every unknown kernel, firmware or baseband exploit. The product must report these boundaries and use integrity attestation/recovery procedures rather than claim 100% detection.

Repository: totalnybet-create/ai-security-guardian
Version: work/p0-security-core
