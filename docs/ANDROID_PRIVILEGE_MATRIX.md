# Android Privilege Capability Matrix

Legend: YES = supported; PARTIAL = supported with limits/user interaction; NO = not available reliably at that privilege level.

| Capability | STANDARD / Play | ADVANCED (ADB/Shizuku) | DEVICE OWNER / Enterprise | ROOT / system |
|---|---|---|---|---|
| Enumerate installed apps | YES with QUERY_ALL_PACKAGES; Play policy approval required | YES | YES | YES |
| Read package metadata, installer, signatures, requested permissions | YES for visible packages | YES | YES | YES |
| Hash installed APK files | PARTIAL; source APK generally readable, OEM differences possible | YES | YES | YES |
| Detect enabled Accessibility services | YES via public AccessibilityManager data | YES | YES | YES |
| Detect active Device Admins | YES via DevicePolicyManager public state | YES | YES | YES |
| Know every overlay grant/state for every app | PARTIAL; declared capability is visible, active/grant visibility is restricted | PARTIAL | stronger policy control, observation still API-dependent | YES/implementation-dependent |
| Revoke another app's runtime permission silently | NO | PARTIAL/YES through privileged package commands | YES for managed policy-supported runtime permissions | YES |
| Suspend/block another app | NO | PARTIAL via privileged package manager | YES via DevicePolicyManager for eligible packages | YES |
| Uninstall another app without user UI | NO; launch uninstall confirmation | PARTIAL | PARTIAL/YES depending provisioning/package-management policy | YES |
| Block an app's network | YES via local VpnService policy if traffic attribution is implemented | YES | YES; can also enforce always-on VPN | YES |
| Capture enterprise DNS/connect logs | NO | NO | YES; DevicePolicyManager network logging | YES |
| Capture Android security logs | NO | NO | YES; DevicePolicyManager security logging | YES |
| Scan all app-private data directories | NO | NO/PARTIAL | NO; Android sandbox still applies | YES, subject to SELinux/system constraints |
| Scan shared/user-selected files | YES within scoped-storage/user grants | YES | YES | YES |
| Block sideloading globally | NO; can guide user/settings | PARTIAL | YES via device policy | YES |
| Enforce approved app allowlist | NO | PARTIAL | YES | YES |
| Enforce Always-On VPN / lockdown | user can configure; app cannot silently own policy | PARTIAL | YES | YES |
| Detect Play Integrity verdict | YES when integrated with backend validation | YES | YES | YES |
| Knox attestation / Knox enterprise policy | Samsung + entitlement/API dependent | same | YES when supported/provisioned | not required |
| Bluetooth device allowlist / profile restrictions | PARTIAL using public Bluetooth APIs and user permissions | PARTIAL | PARTIAL on generic Android; stronger with Samsung Knox | YES/OEM-specific |
| Read private Messenger/WhatsApp/email app databases | NO | NO | NO | technically possible with root but excluded from normal design; privacy risk |
| Analyze URLs/files explicitly shared to Guardian | YES | YES | YES | YES |
| Reliably detect every kernel/baseband zero-day | NO | NO | NO | NO |

## Product modes

### STANDARD
Default Play-compatible architecture. No root. Uses package inspection, public privacy/security APIs, local scanning, user-approved file access, VpnService modules and integrity APIs.

### ADVANCED
Optional local privileged adapter using user-controlled ADB/Shizuku where lawful and appropriate. Never required by the core and never silently enabled.

### DEVICE OWNER / ENTERPRISE
Maximum managed-device edition. Uses Android Enterprise DevicePolicyManager and, on Samsung devices, optional Knox policies. Provisioning is a separate operational step because full Device Owner enrollment may require a clean device/provisioning flow.

### ROOT / SYSTEM
Separate experimental edition only. Not a dependency of the production core. A rooted phone is treated as a changed trust state and must not be presented as more secure merely because more APIs are accessible.

## Mandatory UX rule
If a requested action is impossible at the current privilege level, the UI must say exactly what can and cannot be done and offer the strongest truthful alternative. Never render a successful containment/removal state before verification.
