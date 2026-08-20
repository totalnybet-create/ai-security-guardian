# P2 Quarantine + Install Guard Capability Checkpoint

## Quarantine semantics

AI Security Guardian uses three explicit quarantine outcomes:

- `CONTAINED` — the artifact was copied into app-private storage, the vault copy SHA-256 matched the scanned artifact SHA-256, and Android/DocumentsProvider confirmed deletion of the original document.
- `VAULT_COPY_ONLY` — a verified private vault copy exists, but the original document remains at its source because deletion was not requested, not supported, or not permitted.
- `FAILED` — the copy, integrity verification, metadata persistence, or other required operation failed. The product must not claim containment.

Containment is never inferred from the risk score alone.

The vault stores persistent private metadata for the incident, including source URI/provider, display name, SHA-256, timestamp, risk score, risk level, recommended disposition, evidence IDs, whether original removal was requested, whether it actually succeeded, quarantine outcome, and restore history.

Restore copies the quarantined object to a user-selected writable destination and verifies SHA-256 after writing. The vault object can be removed only after a successful hash-verified restore. A failed or mismatched restore retains the vault copy.

Deleting the original document is a destructive filesystem action and is behind an explicit Human Gate in the UI. Guardian first creates and verifies the vault copy and only then attempts `DocumentsContract.deleteDocument()` when the provider advertises `FLAG_SUPPORTS_DELETE`.

## APK archive parsing

For a user-supplied APK, Guardian can create a bounded temporary private copy and call Android `PackageManager.getPackageArchiveInfo()` with permission/component/signing-certificate flags.

Current APK archive evidence includes:

- package name and version,
- requested permissions,
- SHA-256 of the signing certificate when exposed by PackageManager,
- declared Accessibility service capability,
- declared overlay capability,
- declared request-to-install-packages capability,
- Notification Listener service declaration,
- VPN service declaration,
- exported activity/service/receiver counts.

Current PackageManager archive parsing does **not** claim to recover receiver intent-filter actions such as `BOOT_COMPLETED` from the APK. `bootReceiverDeclared` therefore remains unavailable until a proper Android binary XML manifest parser is integrated and verified.

## Install Guard — STANDARD capability

Standard Android cannot honestly guarantee a manifest receiver for `ACTION_PACKAGE_ADDED` / `ACTION_PACKAGE_REPLACED` after Android 8 background implicit-broadcast restrictions.

The Play/standard implementation therefore uses:

1. **Process realtime monitoring** — a context-registered receiver observes `PACKAGE_ADDED` / `PACKAGE_REPLACED` while the Guardian app process exists.
2. **Process-start reconciliation** — on every Guardian process start, a lightweight baseline of `packageName + lastUpdateTime` is compared with the previous baseline. Only new or changed packages are passed into the full `AndroidAppInspector` + deterministic `RiskEngine`.
3. The initial baseline is stored without inventing historical install events.
4. Update duplication is avoided by ignoring `PACKAGE_ADDED` when `EXTRA_REPLACING=true` and analyzing `PACKAGE_REPLACED` once.
5. HIGH/CRITICAL results produce the existing Android security alert and an audit event.

This implementation does **not** claim guaranteed instant 24/7 install interception when Android has killed the Guardian process. Stronger always-on behavior belongs to a separately justified foreground/enterprise/Device Owner path after policy and battery review.

## Google Play package visibility

The project currently declares `QUERY_ALL_PACKAGES` because app inventory and antivirus/security inspection require broad package visibility. Android documentation lists security/antivirus apps as a rare appropriate use case, but Google Play distribution still requires policy justification and minimum necessary data handling.

## Verification state

- Pure Kotlin P0/P1/P2 risk and pipeline logic: independently compiled and tested outside GitHub Actions.
- Android implementations in this checkpoint: code-complete for the described scope, statically reviewed, but not yet marked Android-SDK-build-verified.
- Full APK assembly and real-device tests remain mandatory before P2 can leave draft/checkpoint state.
