package pl.siedlar.securityguardian.privacy

interface PrivacyInventorySource {
    fun collect(): List<PrivacySnapshot>
}

interface PrivacyAlertSink {
    fun publish(assessment: PrivacyAssessment)
}
