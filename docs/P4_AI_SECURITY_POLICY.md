# P4 AI Security Copilot — Security Policy

## Core invariant

The language model is never a device-state authority and never receives arbitrary shell/system execution.

All executable operations use this fixed path:

`USER/VOICE -> INTENT -> CLOSED SecurityAction -> POLICY -> CAPABILITY -> HUMAN GATE -> EXECUTOR -> VERIFIER -> AUDIT`

An AI provider may propose only a `SecurityAction` that already exists in the closed catalog. It cannot define a new method name, shell command, Android API call, package-management operation or filesystem command.

## Grounding

Device facts are supplied as structured `SecurityFact` records produced by Security Engine modules. An AI provider response declares the IDs of facts it relied on.

If the response references an unknown fact ID, the response is rejected and no action is created.

Provider absence/failure never fabricates device state. The current P4 UI uses the local Polish intent router only; no cloud AI provider is active yet.

## Action allowlist

Each Copilot context contains an explicit `allowedActions` set. Provider output outside that set is rejected before the Command Broker.

The current Android runtime intentionally exposes only actions with real executors and verifiers:

- `RUN_FULL_SCAN`
- `CHECK_PRIVACY`
- `CHECK_APP`
- `CHECK_URL`
- `BLOCK_DOMAIN`
- `ALLOW_DOMAIN_TEMPORARILY`

Other catalog actions exist for policy design but are not presented as executable by the current Android runtime until their executor/verifier path is implemented.

## Human Gate

Policy examples:

- Read-only checks: no confirmation.
- Reversible low-impact policy changes: may execute under policy without destructive confirmation.
- File containment/deletion, restore and uninstall request: explicit UI confirmation.
- Factory reset: Device Owner capability plus biometric and explicit UI confirmation.

Approval is bound to:

- `approvalId`
- `requestId`
- SHA-256 fingerprint of action + sorted arguments + request ID
- approval method
- approval timestamp

Default approval TTL is 2 minutes. Approval IDs are single-use within the replay guard. Changing an argument after approval invalidates the fingerprint.

The broker verifies that an executor and verifier exist before consuming an approval.

## Verification semantics

`ExecutionResult.success=true` is not sufficient to claim the security problem is solved.

Every implemented action has a `SecurityCommandVerifier`. A failed verifier produces `verified=false` and the UI/audit must state that verification did not pass.

For example, `BLOCK_DOMAIN` distinguishes:

- rule persisted + live DNS Guard running,
- rule persisted but DNS Guard not currently running.

The latter is never described as live network enforcement.

`ALLOW_DOMAIN_TEMPORARILY` has explicit expiry and cannot silently override a stronger BLOCK decision. If a stronger policy still wins, the runtime reports the temporary allow as stored but overridden.

## Offline intent path

The current local Polish router recognizes a bounded set of deterministic phrases for:

- full scan,
- privacy check / eavesdropping concern,
- URL check,
- domain block,
- temporary domain allow,
- app/package check.

Unknown natural-language requests perform no action when no AI provider is active.

## Privacy

The current local router and command broker do not require cloud transfer. A future AI provider adapter must receive only the minimum structured facts needed for the turn and must not receive arbitrary private files, full audit logs, secrets or raw device data by default.

API secrets must never be embedded in the APK; any cloud-provider secret must be handled through a controlled backend/proxy or another production-approved secret architecture.

## Pending gates

- Android SDK compilation of `command-android` and Copilot UI,
- emulator and real-device execution/verification tests,
- explicit Android Human Gate UI for destructive actions when those actions are actually wired,
- biometric gate implementation for high-impact privileged operations,
- voice STT/TTS adapter,
- concrete AI provider adapter and backend secret path,
- adversarial prompt-injection/tool-call tests,
- production privacy and Play-policy review.
