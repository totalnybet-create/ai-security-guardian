# P2 Dependency License Gate

Checked on 2026-08-20 against upstream project repositories.

## Approved primary candidates

### Androguard

- Intended role: backend APK/DEX/Android binary XML/resource parsing and static analysis.
- Upstream license: Apache License 2.0.
- Decision: APPROVED CANDIDATE for commercial architecture subject to preserving required notices and dependency-level compliance checks.
- Upstream: https://github.com/androguard/androguard

### YARA-X

- Intended role: rule-based local/backend malware pattern matching.
- Upstream license: BSD 3-Clause.
- Upstream states YARA-X is stable and is the main direction for new YARA development.
- Decision: APPROVED CANDIDATE. Prefer YARA-X over starting new integration work against legacy YARA, subject to Android/native build feasibility and rule-license review.
- Upstream: https://github.com/VirusTotal/yara-x

## Restricted / isolated candidate

### MobSF

- Intended role: optional deep backend analysis/sandbox orchestration.
- Upstream license: GPL-3.0.
- Commercial use is not inherently prohibited by GPL, but distribution/linking/modification can create source-disclosure and reciprocal-license obligations.
- Decision: DO NOT embed or link MobSF into a proprietary mobile distribution at this stage. Treat it only as an optional isolated service after a dedicated legal/compliance review of the exact deployment and distribution model.
- Upstream: https://github.com/MobSF/Mobile-Security-Framework-MobSF

## Additional license invariant

Engine license compatibility is not enough. Malware/signature/rule feeds can carry their own licenses. Every bundled YARA/YARA-X rule source, threat feed, reputation database, and IOC list requires separate provenance and redistribution/commercial-use review before production inclusion.
