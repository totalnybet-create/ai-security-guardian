package pl.siedlar.securityguardian.core

class RiskEngine {
    private val trustedInstallers = setOf(
        "com.android.vending",
        "com.sec.android.app.samsungapps",
        "com.google.android.packageinstaller",
        "com.android.packageinstaller",
    )

    fun assess(app: AppSnapshot): AppAssessment {
        val evidence = mutableListOf<RiskEvidence>()
        var correlationSignals = 0

        fun add(id: String, title: String, detail: String, weight: Int) {
            evidence += RiskEvidence(id, title, detail, weight)
        }

        val sideloaded = !app.isSystemApp && app.installerPackage == null
        val unknownInstaller = !app.isSystemApp && app.installerPackage != null && app.installerPackage !in trustedInstallers

        if (sideloaded) {
            add(
                "installer_missing",
                "Brak zaufanego źródła instalacji",
                "Android nie wskazuje sklepu/instalatora dla tej aplikacji. To może oznaczać sideload lub instalację przez ADB.",
                16,
            )
        } else if (unknownInstaller) {
            add(
                "installer_unknown",
                "Niestandardowe źródło instalacji",
                "Instalator: ${app.installerPackage}. Samo to nie oznacza malware, ale zwiększa potrzebę weryfikacji.",
                8,
            )
        }

        if (!app.isSystemApp) {
            permissionEvidence(app, evidence)
        }

        if (app.declaresAccessibilityService) {
            add(
                "accessibility_capability",
                "Aplikacja zawiera usługę Accessibility",
                "Usługa Accessibility może obserwować interfejs i wykonywać działania, jeśli użytkownik ją włączy.",
                if (app.accessibilityEnabled) 24 else 5,
            )
        }

        if (app.accessibilityEnabled) {
            add(
                "accessibility_enabled",
                "Accessibility jest aktywne",
                "Usługa Accessibility tej aplikacji jest obecnie włączona w systemie.",
                18,
            )
        }

        if (app.deviceAdminActive) {
            add(
                "device_admin_active",
                "Aktywny administrator urządzenia",
                "Aplikacja posiada aktywną rolę Device Admin. Wymaga to szczególnej ostrożności przy nieznanych aplikacjach.",
                18,
            )
        }

        if (app.declaresNotificationListener) {
            add(
                "notification_listener_capability",
                "Możliwość działania jako Notification Listener",
                "Aplikacja deklaruje komponent mogący uzyskać dostęp do treści powiadomień po zgodzie użytkownika.",
                4,
            )
        }

        if (app.declaresVpnService) {
            add(
                "vpn_capability",
                "Możliwość działania jako VPN",
                "Aplikacja deklaruje usługę VPN. Jest to normalne dla wielu narzędzi, ale daje szeroką widoczność ruchu po włączeniu.",
                2,
            )
        }

        val wantsOverlay = "android.permission.SYSTEM_ALERT_WINDOW" in app.requestedPermissions
        val wantsInstallPackages = "android.permission.REQUEST_INSTALL_PACKAGES" in app.requestedPermissions
        val hasMic = "android.permission.RECORD_AUDIO" in app.grantedPermissions
        val hasCamera = "android.permission.CAMERA" in app.grantedPermissions

        if (app.accessibilityEnabled && wantsOverlay) {
            add(
                "corr_accessibility_overlay",
                "Korelacja: Accessibility + overlay",
                "Połączenie aktywnego Accessibility z możliwością nakładania okien może służyć do sterowania lub przechwytywania interakcji.",
                20,
            )
            correlationSignals++
        }

        if (app.accessibilityEnabled && wantsInstallPackages) {
            add(
                "corr_accessibility_installer",
                "Korelacja: Accessibility + instalowanie APK",
                "Połączenie kontroli interfejsu z możliwością instalowania pakietów jest charakterystyczne dla części dropperów i RAT-ów.",
                22,
            )
            correlationSignals++
        }

        if (app.accessibilityEnabled && sideloaded) {
            add(
                "corr_accessibility_sideload",
                "Korelacja: sideload + aktywne Accessibility",
                "Aplikacja bez zaufanego instalatora ma aktywną usługę Accessibility.",
                18,
            )
            correlationSignals++
        }

        if (app.deviceAdminActive && sideloaded) {
            add(
                "corr_admin_sideload",
                "Korelacja: sideload + Device Admin",
                "Nieznane źródło instalacji i aktywny administrator urządzenia wymagają natychmiastowej weryfikacji.",
                16,
            )
            correlationSignals++
        }

        if (app.accessibilityEnabled && hasMic && hasCamera) {
            add(
                "corr_accessibility_mic_camera",
                "Korelacja: kontrola + mikrofon + kamera",
                "Aplikacja ma aktywne Accessibility oraz przyznany mikrofon i kamerę. Taki zestaw może umożliwiać szeroką obserwację urządzenia.",
                12,
            )
            correlationSignals++
        }

        if (wantsOverlay && app.declaresNotificationListener && sideloaded) {
            add(
                "corr_overlay_notifications_sideload",
                "Korelacja: overlay + powiadomienia + sideload",
                "Ta kombinacja zwiększa ryzyko phishingu ekranowego lub przechwytywania informacji.",
                10,
            )
            correlationSignals++
        }

        val score = evidence.sumOf { it.weight }.coerceIn(0, 100)
        val confidence = when {
            score == 0 -> 55
            else -> (55 + evidence.size * 5 + correlationSignals * 10).coerceIn(55, 95)
        }

        return AppAssessment(
            app = app,
            riskScore = score,
            riskLevel = RiskLevel.fromScore(score),
            confidence = confidence,
            evidence = evidence.sortedByDescending { it.weight },
        )
    }

    private fun permissionEvidence(app: AppSnapshot, evidence: MutableList<RiskEvidence>) {
        val granted = app.grantedPermissions
        val requested = app.requestedPermissions

        val riskyGranted = listOf(
            Triple("android.permission.READ_SMS", "Dostęp do SMS", 8),
            Triple("android.permission.SEND_SMS", "Wysyłanie SMS", 6),
            Triple("android.permission.RECEIVE_SMS", "Odbieranie SMS", 4),
            Triple("android.permission.READ_CALL_LOG", "Dostęp do historii połączeń", 8),
            Triple("android.permission.WRITE_CALL_LOG", "Modyfikacja historii połączeń", 8),
            Triple("android.permission.READ_CONTACTS", "Dostęp do kontaktów", 3),
            Triple("android.permission.READ_PHONE_STATE", "Dostęp do stanu telefonu", 3),
            Triple("android.permission.RECORD_AUDIO", "Dostęp do mikrofonu", 2),
            Triple("android.permission.CAMERA", "Dostęp do kamery", 2),
            Triple("android.permission.ACCESS_FINE_LOCATION", "Dokładna lokalizacja", 2),
        )

        riskyGranted.forEach { (permission, title, weight) ->
            if (permission in granted) {
                evidence += RiskEvidence(
                    id = "granted:$permission",
                    title = title,
                    detail = "Uprawnienie jest obecnie przyznane. Samo uprawnienie nie oznacza złośliwego działania.",
                    weight = weight,
                )
            }
        }

        if ("android.permission.SYSTEM_ALERT_WINDOW" in requested) {
            evidence += RiskEvidence(
                "requested:overlay",
                "Możliwość wyświetlania nad innymi aplikacjami",
                "Manifest deklaruje SYSTEM_ALERT_WINDOW. P0 widzi deklarowaną możliwość; nie udaje pełnej wiedzy o aktualnym stanie przyznania dla każdej aplikacji.",
                7,
            )
        }

        if ("android.permission.REQUEST_INSTALL_PACKAGES" in requested) {
            evidence += RiskEvidence(
                "requested:install_packages",
                "Możliwość inicjowania instalacji APK",
                "Manifest deklaruje REQUEST_INSTALL_PACKAGES. Jest to istotne w połączeniu z innymi sygnałami.",
                9,
            )
        }
    }
}
