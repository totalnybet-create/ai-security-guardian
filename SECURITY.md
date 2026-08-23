# Security Policy and Invariants

AI Security Guardian is a defensive Android security product. These rules are architectural invariants.

1. Never report a security capability that is not actually implemented and verified.
2. The LLM is an explanation and intent layer, never a privileged shell.
3. Every action follows: Intent -> Policy -> Capability Check -> Human Gate -> Executor -> Verification -> Audit.
4. Destructive actions require explicit user confirmation; factory reset additionally requires strong local authentication.
5. Core protection must not depend on root.
6. Root/privileged/enterprise capabilities live in separate adapters and variants.
7. Device state claims must come from collected evidence, not AI inference.
8. Security verdicts require evidence and confidence; a single ordinary permission is not malware proof.
9. Local-first processing is the default. Cloud transfer must be explicit, purpose-limited and encrypted.
10. Secrets never ship in the APK. External provider secrets are held behind a backend proxy.
11. Failures in optional engines must fail safe without silently breaking normal Internet or device operation.
12. After containment/removal, rescan and verify clean state before closing an incident.
13. If device integrity cannot be established, report TRUST UNKNOWN/FAILED rather than "safe".
14. No active malware is used on a normal development or personal device; use benign simulators/test artifacts.
