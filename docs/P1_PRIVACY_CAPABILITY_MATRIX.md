# P1 Privacy Capability Matrix

P1 never equates a declared capability with active misuse.

| Signal | Standard app | Device Owner / Enterprise | P1 interpretation |
|---|---|---|---|
| Microphone permission granted | Yes, for visible packages | Yes | CAPABILITY only; not proof of active recording |
| Camera permission granted | Yes, for visible packages | Yes | CAPABILITY only; not proof of active recording |
| Fine/background location granted | Yes, for visible packages | Yes | CAPABILITY / privacy exposure |
| Accessibility service active | Yes, via public accessibility APIs | Yes | ACTIVE capability |
| Device Admin active | Yes, via DevicePolicyManager | Yes | ACTIVE administrative capability |
| Notification Listener active | Yes, via `NotificationManagerCompat.getEnabledListenerPackages()` | Yes | ACTIVE capability |
| Overlay declared | Yes, from manifest/package metadata | Yes | CAPABILITY only; standard P1 does not pretend to know another app's current overlay grant |
| Overlay grant for arbitrary other app | Not reliably exposed by a standard public per-package query | Stronger management paths may apply | UNKNOWN in standard mode |
| VPN service declared | Yes | Yes | CAPABILITY only |
| Which third-party VPN service is currently active | Limited / not reliably attributable in standard mode | Stronger network/enterprise telemetry may apply | UNKNOWN unless independently evidenced |
| Battery optimization exemption | Yes, `PowerManager.isIgnoringBatteryOptimizations(packageName)` | Yes | Context signal for persistent background behavior |
| Other app is using microphone right now | No reliable universal standard-app feed | Enterprise/integrity/vendor signals may improve coverage | UNKNOWN unless evidenced |
| Other app is using camera right now | No reliable universal standard-app feed | Enterprise/integrity/vendor signals may improve coverage | UNKNOWN unless evidenced |
| Other app is capturing the screen right now | No universal standard-app feed | Play Integrity app access risk / enterprise signals where available | UNKNOWN unless evidenced |

## UI rule

Every privacy fact is tagged internally as one of:

- `ACTIVE` — current state is directly evidenced.
- `CAPABILITY` — application can potentially perform the action, but active use is not proven.
- `UNKNOWN` — Android does not expose enough trustworthy evidence at the current privilege level.
- `NOT_PRESENT` — evidence confirms the capability/state is absent.

The AI layer may explain these states but may not upgrade `CAPABILITY` or `UNKNOWN` to `ACTIVE` without new Security Engine evidence.
