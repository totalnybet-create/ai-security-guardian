# P3 Network Guard — Android Capability Matrix

## STANDARD app

### VpnService firewall path — AVAILABLE WITH USER CONSENT

Android `VpnService` is the standard platform mechanism for creating a local VPN/TUN interface. The VPN service must be declared with `android.permission.BIND_VPN_SERVICE` and the `android.net.VpnService` service action. User consent is obtained through `VpnService.prepare()` unless the VPN is already authorized.

On Android 8.0+ a VPN app started in the background receives only a short allowlist window and must promote the VPN service to a foreground service or Android will stop it.

Guardian may use this path for local packet filtering, but it must not establish a TUN interface until its packet forwarding path is actually ready. Establishing a VPN and then failing to forward allowed traffic would create a self-inflicted connectivity outage.

### Always-on VPN — USER/SETTINGS CAPABILITY

A supported VPN app can be selected by the user as always-on in Android VPN settings. Guardian can report whether its running `VpnService` is in always-on mode where the API exposes that state.

### Lockdown VPN — USER/SETTINGS CAPABILITY, HIGH IMPACT

Lockdown prevents apps from bypassing the VPN, including during VPN failure. This can break networking if the VPN implementation fails. Guardian must therefore not silently enable or imply lockdown protection in the STANDARD edition.

### Payload visibility

A local VPN sees traffic routed through its TUN interface, but normal TLS/QUIC application payloads remain encrypted. Guardian must not claim that it can read arbitrary HTTPS message contents without a separate interception architecture, certificate trust changes and explicit policy review. The intended product direction is metadata/domain/IP/reputation/filtering, not silent TLS interception.

## DEVICE OWNER / PROFILE OWNER

A Device/Profile Owner can programmatically configure an always-on VPN package through `DevicePolicyManager.setAlwaysOnVpnPackage()`, including lockdown mode on supported Android versions. This belongs to the enterprise/managed-device adapter and is not a STANDARD capability.

Lockdown has a documented availability risk: VPN/provider failure can prevent normal apps from networking. Enterprise policy must therefore include recovery/allowlist procedures before enabling it.

## ROOT / SYSTEM

Root/system variants may support different packet-filtering mechanisms, but they are explicitly out of the STANDARD core and must not be required for normal Guardian operation.

## P3 implementation gate

Current verified P3 code is the pure Kotlin deterministic policy/threat-intelligence core only. The Android VpnService transport/enforcement adapter is not yet presented as active protection. A visible firewall switch must not ship until all of the following are verified:

1. user consent flow,
2. foreground-service lifecycle,
3. stable TUN establishment,
4. allowed-packet forwarding,
5. block enforcement,
6. DNS/IP/domain evidence collection,
7. failure recovery without unnecessary Internet loss,
8. battery/performance behavior,
9. revoke/restart handling,
10. Android SDK + emulator + real-device regression tests.
