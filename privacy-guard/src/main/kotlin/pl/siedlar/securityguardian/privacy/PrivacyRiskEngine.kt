package pl.siedlar.securityguardian.privacy

import pl.siedlar.securityguardian.core.RiskLevel

class PrivacyRiskEngine {
    fun assess(snapshot: PrivacySnapshot): PrivacyAssessment {
        val evidence = mutableListOf<PrivacyEvidence>()
        var correlations = 0

        fun add(id: String, title: String, detail: String, weight: Int) {
            evidence += PrivacyEvidence(id, title, detail, weight)
        }

        if (snapshot.microphoneGranted) {
            add(
                "mic_granted",
                "Dostęp do mikrofonu",
                "Aplikacja ma przyznany dostęp do mikrofonu. Samo uprawnienie nie oznacza podsłuchu.",
                3,
            )
        }

        if (snapshot.cameraGranted) {
            add(
                "camera_granted",
                "Dostęp do kamery",
                "Aplikacja ma przyznany dostęp do kamery. Samo uprawnienie nie oznacza nagrywania.",
                3,
            )
        }

        if (snapshot.backgroundLocationGranted) {
            add(
                "background_location",
                "Lokalizacja w tle",
                "Aplikacja może korzystać z lokalizacji również poza aktywnym ekranem aplikacji.",
                7,
            )
        } else if (snapshot.fineLocationGranted) {
            add(
                "fine_location",
                "Dokładna lokalizacja",
                "Aplikacja ma dostęp do dokładnej lokalizacji podczas dozwolonego użycia.",
                2,
            )
        }

        if (snapshot.accessibilityEnabled) {
            add(
                "accessibility_active",
                "Aktywne Accessibility",
                "Usługa Accessibility aplikacji jest aktywna i może obserwować lub sterować interfejsem w zakresie przyznanym przez Android.",
                22,
            )
        }

        if (snapshot.deviceAdminActive) {
            add(
                "device_admin_active",
                "Aktywny administrator urządzenia",
                "Aplikacja ma aktywną rolę Device Admin, co zwiększa jej możliwości administracyjne.",
                16,
            )
        }

        if (snapshot.overlayCapabilityDeclared) {
            add(
                "overlay_capability",
                "Możliwość nakładania okien",
                "Manifest deklaruje możliwość wyświetlania elementów nad innymi aplikacjami. Standardowy tryb nie udaje wiedzy o aktualnym grantcie dla obcej aplikacji.",
                6,
            )
        }

        if (snapshot.notificationListenerEnabled) {
            add(
                "notification_listener_active",
                "Aktywny dostęp do powiadomień",
                "Aplikacja jest obecnie wśród włączonych Notification Listenerów i może otrzymywać treść powiadomień zgodnie z API Androida.",
                14,
            )
        } else if (snapshot.notificationListenerDeclared) {
            add(
                "notification_listener_capability",
                "Możliwość dostępu do powiadomień",
                "Aplikacja deklaruje usługę Notification Listener, ale P1 nie traktuje samej deklaracji jako aktywnego dostępu.",
                3,
            )
        }

        if (snapshot.vpnServiceDeclared) {
            add(
                "vpn_capability",
                "Możliwość działania jako VPN",
                "Aplikacja deklaruje usługę VPN. P1 nie twierdzi, że VPN jest aktywny bez niezależnego potwierdzenia.",
                2,
            )
        }

        if (snapshot.batteryOptimizationExempt) {
            add(
                "battery_exempt",
                "Wyłączenie z optymalizacji baterii",
                "Aplikacja może łatwiej utrzymywać pracę w tle. To sygnał kontekstowy, nie dowód złośliwości.",
                2,
            )
        }

        if (snapshot.accessibilityEnabled && snapshot.overlayCapabilityDeclared) {
            add(
                "corr_accessibility_overlay",
                "Korelacja: Accessibility + overlay",
                "Połączenie aktywnego Accessibility z możliwością nakładania okien zwiększa ryzyko sterowania interfejsem lub phishingu ekranowego.",
                22,
            )
            correlations++
        }

        if (snapshot.accessibilityEnabled && snapshot.notificationListenerEnabled) {
            add(
                "corr_accessibility_notifications",
                "Korelacja: Accessibility + powiadomienia",
                "Aplikacja może jednocześnie obserwować interfejs oraz odbierać treść powiadomień.",
                18,
            )
            correlations++
        }

        if (snapshot.accessibilityEnabled && snapshot.microphoneGranted && snapshot.cameraGranted) {
            add(
                "corr_accessibility_mic_camera",
                "Korelacja: kontrola + mikrofon + kamera",
                "Aktywne Accessibility oraz przyznany mikrofon i kamera tworzą szeroki zestaw możliwości wymagający szczególnej weryfikacji.",
                18,
            )
            correlations++
        }

        if (snapshot.notificationListenerEnabled && snapshot.overlayCapabilityDeclared) {
            add(
                "corr_notifications_overlay",
                "Korelacja: powiadomienia + overlay",
                "Dostęp do powiadomień połączony z możliwością nakładania okien zwiększa ryzyko przechwytywania lub podszywania się pod interfejs.",
                12,
            )
            correlations++
        }

        if (snapshot.deviceAdminActive && snapshot.accessibilityEnabled) {
            add(
                "corr_admin_accessibility",
                "Korelacja: Device Admin + Accessibility",
                "Jednoczesne uprawnienia administracyjne i aktywne Accessibility znacząco zwiększają zakres kontroli aplikacji.",
                18,
            )
            correlations++
        }

        val score = evidence.sumOf { it.weight }.coerceIn(0, 100)
        val confidence = when {
            score == 0 -> 55
            correlations > 0 -> (70 + correlations * 7 + evidence.size * 2).coerceIn(70, 96)
            else -> (55 + evidence.size * 4).coerceIn(55, 80)
        }

        return PrivacyAssessment(
            snapshot = snapshot,
            riskScore = score,
            riskLevel = RiskLevel.fromScore(score),
            confidence = confidence,
            evidence = evidence.sortedByDescending { it.weight },
        )
    }
}
