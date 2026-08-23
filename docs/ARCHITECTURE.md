# Production Architecture

## Editions
- `play`: standard Android/Google Play compatible edition.
- `enterprise`: Device Owner / Android Enterprise adapter, optional Samsung Knox adapter.
- `advanced`: optional ADB/Shizuku adapter, isolated from the core.
- `root`: optional separate variant; never required for core protection.

## Layering

### UI
Jetpack Compose. Light-only visual system for the first product edition. UI displays evidence-backed state and exposes only real actions.

### Core Security
Pure Kotlin domain layer. Owns risk scoring, security verdicts, incident state machine, action policy contracts and deterministic security score formulas. No Android framework dependency and no AI dependency.

### Android Sensors / Collectors
Adapters collect installed packages, install sources, certificates, APK hashes, requested/granted permissions, enabled Accessibility services, active Device Admin state and later privacy/integrity/network signals.

### Policy and Capability Engine
Before an action executes it resolves current edition/capabilities. Unsupported operations return an explicit `UNAVAILABLE` result with a reason, never a simulated success.

### Human Gate
Destructive operations require explicit confirmation. High-risk system recovery operations require stronger local authentication.

### Executors
Edition-specific implementations perform supported actions: open settings/uninstall UI in Standard, DevicePolicyManager actions in Enterprise, optional privileged adapters in Advanced/Root.

### Verification
Every containment/removal action has a paired verifier. Incident cannot transition to resolved without verification.

### Audit
Append-only structured local audit trail in app-private storage. Cloud export is optional and explicit.

### AI Copilot
Receives structured read-only security facts and allowed action intents. It explains evidence and proposes actions. It cannot invoke arbitrary shell or Android APIs directly.

### Provider abstractions
AI, threat intelligence, reputation and future cloud sandbox providers are interfaces. Provider changes do not alter domain logic.

## P0 implemented modules
- `app`: Compose dashboard and scan orchestration wiring.
- `core-security`: models, deterministic risk engine, scan service, audit/notifier contracts and unit tests.
- `app-inspector`: real Android package/app/permission inspection.
- `audit-log`: app-private JSONL audit logger.
- `notifications`: real Android notification channel and threat alerts.

## Next modules
- P1: `permission-guard`, `privacy-guard`, `device-integrity`.
- P2: `file-scanner`, `install-guard`, `reputation-engine`, `quarantine`, static APK analysis.
- P3: `network-guard`, `threat-intelligence`, phishing/link analysis.
- P4: `ai-copilot`, `voice`, policy/human-gate UX.
- P5: enterprise/device-owner/Knox containment adapters.

## P0 scan path
`Compose UI -> FullScanService -> AndroidAppInspector -> RiskEngine -> AuditLog + ThreatNotifier -> DeviceScanReport -> UI`

## Risk discipline
- Requested permission alone is evidence, not a malware verdict.
- High/critical results require stronger capabilities or multiple correlated signals.
- System apps are not treated as sideloaded merely because installer metadata is absent.
- P0 exposes an `App Security Score`, not a fake whole-device score. Whole-device score is enabled only when privacy/network/integrity categories are implemented.

## Build baseline
- targetSdk 36 for Android 16 policy compliance.
- compileSdk 36 for the initial stable P0 line.
- minSdk 23.
- AGP 8.13.2, Gradle 8.13, JDK 17, Kotlin 2.3.21.
- Jetpack Compose with pinned BOM; no dynamic dependency versions.
