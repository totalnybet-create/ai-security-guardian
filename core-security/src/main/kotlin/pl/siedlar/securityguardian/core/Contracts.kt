package pl.siedlar.securityguardian.core

interface AppInventorySource {
    fun collect(): List<AppSnapshot>
}

interface AuditSink {
    fun append(event: AuditEvent)
}

interface SecurityAlertSink {
    fun publish(assessment: AppAssessment)
}
