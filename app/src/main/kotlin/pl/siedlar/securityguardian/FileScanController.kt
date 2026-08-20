package pl.siedlar.securityguardian

import android.content.Context
import android.net.Uri
import pl.siedlar.securityguardian.audit.JsonlAuditLogger
import pl.siedlar.securityguardian.files.AndroidApkArchiveInspector
import pl.siedlar.securityguardian.files.AndroidUriArtifactFactory
import pl.siedlar.securityguardian.files.AndroidUriMalwareScanner
import pl.siedlar.securityguardian.malware.CompositeReputationEngine
import pl.siedlar.securityguardian.malware.LocalArtifactPreprocessor
import pl.siedlar.securityguardian.malware.MalwareAssessment
import pl.siedlar.securityguardian.malware.MalwareAssessmentService
import pl.siedlar.securityguardian.malware.MalwareRiskEngine
import pl.siedlar.securityguardian.notifications.AndroidMalwareAlertSink
import pl.siedlar.securityguardian.quarantine.AndroidFileQuarantine
import pl.siedlar.securityguardian.quarantine.QuarantineRecord

class FileScanController(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val scanner = AndroidUriMalwareScanner(
        artifactFactory = AndroidUriArtifactFactory(appContext),
        preprocessor = LocalArtifactPreprocessor(),
        assessmentService = MalwareAssessmentService(
            reputationEngine = CompositeReputationEngine(emptyList()),
            riskEngine = MalwareRiskEngine(),
            auditSink = JsonlAuditLogger(appContext),
            alertSink = AndroidMalwareAlertSink(appContext),
        ),
        apkArchiveInspector = AndroidApkArchiveInspector(appContext),
    )
    private val quarantine = AndroidFileQuarantine(appContext)

    fun scan(uri: Uri): MalwareAssessment = scanner.scan(
        uri = uri,
        trustedSource = false,
    )

    fun quarantine(
        uri: Uri,
        assessment: MalwareAssessment,
        removeOriginalAfterVerifiedCopy: Boolean,
    ): QuarantineRecord = quarantine.quarantine(
        uri = uri,
        expectedSha256 = assessment.artifact.sha256,
        displayName = assessment.artifact.displayName,
        removeOriginalAfterVerifiedCopy = removeOriginalAfterVerifiedCopy,
    )
}
