# P4 AI Security Copilot — Local Verification

Independent pure-Kotlin verification performed outside GitHub Actions on 2026-08-20.

Environment:

- local Kotlin/JVM compiler
- OpenJDK
- no Android SDK required for the verified core paths

Verification artifact SHA-256:

- Command Broker policy/approval regression: `7f337df36c36a732a044d336f18d78375d72958dd49b3711dfd464f6e1ab553e`
- Grounded Copilot/offline-router regression: `441e96d5224406f6d69bd8d8fc3f9919b57c7ad23a356d6da8f3ab9f3663cf1d`

Observed outputs:

`P4_COMMAND_BROKER_TEST_OK executed=1 replayBlocked=true mutationBlocked=true`

`P4_COPILOT_TEST_OK offline=CHECK_URL ungroundedBlocked=true actionAllowlist=true`

Verified scenarios:

1. A read-only security action can execute without a destructive Human Gate when required capability is present.
2. Missing capability denies execution before the executor runs.
3. Destructive policy requires the configured Human Gate.
4. Approval is bound to the full request fingerprint; changing arguments after approval is rejected.
5. Approval is single-use; replay is rejected.
6. Expired approval is rejected.
7. Factory reset policy requires Device Owner-level privilege/capabilities plus biometric+explicit approval.
8. Offline Polish routing can create a closed `CHECK_URL` command without a cloud provider.
9. When no provider exists and the local router does not recognize a request, no security action is invented.
10. AI provider output referencing a fact not supplied by Security Engine is rejected.
11. AI provider output proposing an action outside the per-turn allowlist is rejected.
12. A grounded provider proposal becomes only a closed `SecurityAction` request; no arbitrary method/shell path exists.

Post-verification hardening applied and statically reviewed:

- executor/verifier availability is checked before a HumanApproval is consumed,
- nullable Android runtime score fields use explicit null/range checks,
- permanent domain BLOCK checks canonicalize the domain,
- local IOC snapshot is reloaded for effective network-policy evaluation,
- temporary ALLOW is verified by expiry and effective policy; stronger BLOCK remains visible instead of being silently overridden.

Android implementation added but still awaiting Android SDK compiler/device verification:

- `command-android` runtime,
- real executors/verifiers for full scan, privacy, app, URL, BLOCK domain and temporary ALLOW,
- light `CopilotActivity`,
- dashboard entry,
- command audit adapter into the existing JSONL audit,
- explicit result distinction between rule persistence and live DNS enforcement.

Important invariants:

- AI is not a device fact source.
- No arbitrary shell/system execution is exposed to AI.
- Unimplemented actions are not advertised by the current Android runtime.
- `ExecutionResult.success` does not equal a verified clean state.
- Cloud AI and voice are not currently active and must not be claimed as deployed.

Still pending:

- Android SDK/APK compilation,
- emulator and real-device command execution/verification,
- destructive-action Human Gate UI when destructive executors are wired,
- biometric gate for high-impact privileged operations,
- voice STT/TTS,
- concrete AI provider/backend secret integration,
- prompt-injection/tool-safety regression,
- final P4 production/security/privacy review.
