package pl.siedlar.securityguardian.files

import android.Manifest
import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import pl.siedlar.securityguardian.malware.ArtifactCandidate
import java.io.File
import java.security.MessageDigest

data class ApkArchiveReport(
    val packageName: String,
    val versionName: String?,
    val requestedPermissions: Set<String>,
    val accessibilityServiceDeclared: Boolean,
    val overlayCapabilityDeclared: Boolean,
    val installPackagesCapabilityDeclared: Boolean,
    val notificationListenerDeclared: Boolean,
    val vpnServiceDeclared: Boolean,
    val exportedActivityCount: Int,
    val exportedServiceCount: Int,
    val exportedReceiverCount: Int,
    val signingCertificateSha256: String?,
)

class AndroidApkArchiveInspector(
    context: Context,
    private val maxBytes: Long = 512L * 1024L * 1024L,
) {
    private val appContext = context.applicationContext
    private val packageManager: PackageManager = appContext.packageManager
    private val workDir = File(appContext.cacheDir, "apk-analysis").apply {
        check(exists() || mkdirs()) { "Cannot create APK analysis cache directory" }
    }

    init {
        require(maxBytes > 0)
    }

    fun inspect(candidate: ArtifactCandidate): ApkArchiveReport? {
        val temp = File.createTempFile("guardian-apk-", ".apk", workDir)
        return try {
            candidate.sizeBytes?.let { declared ->
                if (declared > maxBytes) error("APK exceeds parser limit of $maxBytes bytes")
            }
            candidate.content.openStream().use { input ->
                temp.outputStream().buffered().use { output ->
                    val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                    var total = 0L
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        total += read
                        if (total > maxBytes) error("APK exceeds parser limit of $maxBytes bytes")
                        output.write(buffer, 0, read)
                    }
                }
            }

            val packageInfo = packageArchiveInfo(temp) ?: return null
            val permissions = packageInfo.requestedPermissions?.toSet().orEmpty()
            val services = packageInfo.services.orEmpty()

            ApkArchiveReport(
                packageName = packageInfo.packageName,
                versionName = packageInfo.versionName,
                requestedPermissions = permissions,
                accessibilityServiceDeclared = services.any {
                    it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
                },
                overlayCapabilityDeclared = Manifest.permission.SYSTEM_ALERT_WINDOW in permissions,
                installPackagesCapabilityDeclared = Manifest.permission.REQUEST_INSTALL_PACKAGES in permissions,
                notificationListenerDeclared = services.any {
                    it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
                },
                vpnServiceDeclared = services.any {
                    it.permission == "android.permission.BIND_VPN_SERVICE"
                },
                exportedActivityCount = packageInfo.activities.orEmpty().count { it.exported },
                exportedServiceCount = services.count { it.exported },
                exportedReceiverCount = packageInfo.receivers.orEmpty().count { it.exported },
                signingCertificateSha256 = signingCertificateSha256(packageInfo),
            )
        } finally {
            temp.delete()
        }
    }

    private fun packageArchiveInfo(file: File): PackageInfo? {
        val flags = (
            PackageManager.GET_PERMISSIONS or
                PackageManager.GET_ACTIVITIES or
                PackageManager.GET_SERVICES or
                PackageManager.GET_RECEIVERS or
                PackageManager.GET_SIGNING_CERTIFICATES
            ).toLong()

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageArchiveInfo(
                file.absolutePath,
                PackageManager.PackageInfoFlags.of(flags),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageArchiveInfo(file.absolutePath, flags.toInt())
        }
    }

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? = runCatching {
        val bytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val signingInfo = packageInfo.signingInfo ?: return@runCatching null
            val signers = if (signingInfo.hasMultipleSigners()) {
                signingInfo.apkContentsSigners
            } else {
                signingInfo.signingCertificateHistory
            }
            signers.firstOrNull()?.toByteArray()
        } else {
            @Suppress("DEPRECATION")
            packageInfo.signatures?.firstOrNull()?.toByteArray()
        }
        bytes?.let { certificate ->
            MessageDigest.getInstance("SHA-256")
                .digest(certificate)
                .joinToString("") { byte -> "%02x".format(byte) }
        }
    }.getOrNull()
}
