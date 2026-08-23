package pl.siedlar.securityguardian.privacy

import pl.siedlar.securityguardian.core.RiskLevel

enum class ObservationState {
    ACTIVE,
    CAPABILITY,
    UNKNOWN,
    NOT_PRESENT,
}

data class PrivacySnapshot(
    val packageName: String,
    val label: String,
    val microphoneGranted: Boolean,
    val cameraGranted: Boolean,
    val fineLocationGranted: Boolean,
    val backgroundLocationGranted: Boolean,
    val accessibilityEnabled: Boolean,
    val deviceAdminActive: Boolean,
    val overlayCapabilityDeclared: Boolean,
    val notificationListenerDeclared: Boolean,
    val notificationListenerEnabled: Boolean,
    val vpnServiceDeclared: Boolean,
    val batteryOptimizationExempt: Boolean,
    val microphoneActiveState: ObservationState = ObservationState.UNKNOWN,
    val cameraActiveState: ObservationState = ObservationState.UNKNOWN,
    val screenCaptureState: ObservationState = ObservationState.UNKNOWN,
)

data class PrivacyEvidence(
    val id: String,
    val title: String,
    val detail: String,
    val weight: Int,
)

data class PrivacyAssessment(
    val snapshot: PrivacySnapshot,
    val riskScore: Int,
    val riskLevel: RiskLevel,
    val confidence: Int,
    val evidence: List<PrivacyEvidence>,
)
