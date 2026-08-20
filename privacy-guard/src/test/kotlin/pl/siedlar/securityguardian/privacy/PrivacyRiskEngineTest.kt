package pl.siedlar.securityguardian.privacy

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import pl.siedlar.securityguardian.core.RiskLevel

class PrivacyRiskEngineTest {
    private val engine = PrivacyRiskEngine()

    @Test
    fun ordinaryCameraPermissionDoesNotBecomeMalwareVerdict() {
        val result = engine.assess(
            snapshot(camera = true),
        )

        assertEquals(3, result.riskScore)
        assertEquals(RiskLevel.SAFE, result.riskLevel)
        assertTrue(result.evidence.any { it.id == "camera_granted" })
    }

    @Test
    fun accessibilityOverlayAndNotificationsBecomeHighOrCritical() {
        val result = engine.assess(
            snapshot(
                accessibility = true,
                overlay = true,
                notificationListenerEnabled = true,
                microphone = true,
                camera = true,
            ),
        )

        assertTrue(result.riskScore >= 75)
        assertEquals(RiskLevel.CRITICAL, result.riskLevel)
        assertTrue(result.evidence.any { it.id == "corr_accessibility_overlay" })
        assertTrue(result.evidence.any { it.id == "corr_accessibility_notifications" })
        assertTrue(result.evidence.any { it.id == "corr_accessibility_mic_camera" })
    }

    @Test
    fun unknownRuntimeUsageIsNotInventedAsActive() {
        val input = snapshot(microphone = true, camera = true)
        val result = engine.assess(input)

        assertEquals(ObservationState.UNKNOWN, result.snapshot.microphoneActiveState)
        assertEquals(ObservationState.UNKNOWN, result.snapshot.cameraActiveState)
        assertTrue(result.evidence.none { it.id.contains("active_usage") })
    }

    private fun snapshot(
        microphone: Boolean = false,
        camera: Boolean = false,
        fineLocation: Boolean = false,
        backgroundLocation: Boolean = false,
        accessibility: Boolean = false,
        deviceAdmin: Boolean = false,
        overlay: Boolean = false,
        notificationListenerDeclared: Boolean = false,
        notificationListenerEnabled: Boolean = false,
        vpn: Boolean = false,
        batteryExempt: Boolean = false,
    ) = PrivacySnapshot(
        packageName = "test.app",
        label = "Test App",
        microphoneGranted = microphone,
        cameraGranted = camera,
        fineLocationGranted = fineLocation,
        backgroundLocationGranted = backgroundLocation,
        accessibilityEnabled = accessibility,
        deviceAdminActive = deviceAdmin,
        overlayCapabilityDeclared = overlay,
        notificationListenerDeclared = notificationListenerDeclared,
        notificationListenerEnabled = notificationListenerEnabled,
        vpnServiceDeclared = vpn,
        batteryOptimizationExempt = batteryExempt,
    )
}
