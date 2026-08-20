package pl.siedlar.securityguardian.inspector

import android.Manifest
import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.view.accessibility.AccessibilityManager
import pl.siedlar.securityguardian.core.AppInventorySource
import pl.siedlar.securityguardian.core.AppSnapshot
import java.io.File
import java.io.FileInputStream
import java.security.MessageDigest

class AndroidAppInspector(
    private val context: Context,
) : AppInventorySource {

    private val packageManager: PackageManager = context.packageManager

    override fun collect(): List<AppSnapshot> {
        val enabledAccessibilityPackages = enabledAccessibilityPackages()
        val activeDeviceAdmins = activeDeviceAdminPackages()

        return installedPackages()
            .mapNotNull { packageInfo ->
                runCatching {
                    toSnapshot(
                        packageInfo = packageInfo,
                        enabledAccessibilityPackages = enabledAccessibilityPackages,
                        activeDeviceAdmins = activeDeviceAdmins,
                    )
                }.getOrNull()
            }
            .sortedBy { it.label.lowercase() }
    }

    fun collectPackage(packageName: String): AppSnapshot? {
        val packageInfo = runCatching { installedPackage(packageName) }.getOrNull() ?: return null
        return runCatching {
            toSnapshot(
                packageInfo = packageInfo,
                enabledAccessibilityPackages = enabledAccessibilityPackages(),
                activeDeviceAdmins = activeDeviceAdminPackages(),
            )
        }.getOrNull()
    }

    private fun installedPackages(): List<PackageInfo> {
        val flags = packageInfoFlags()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(flags))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(flags.toInt())
        }
    }

    private fun installedPackage(packageName: String): PackageInfo {
        val flags = packageInfoFlags()
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getPackageInfo(
                packageName,
                PackageManager.PackageInfoFlags.of(flags),
            )
        } else {
            @Suppress("DEPRECATION")
            packageManager.getPackageInfo(packageName, flags.toInt())
        }
    }

    private fun packageInfoFlags(): Long = (
        PackageManager.GET_PERMISSIONS or
            PackageManager.GET_SERVICES or
            PackageManager.GET_SIGNATURES or
            PackageManager.GET_SIGNING_CERTIFICATES
        ).toLong()

    private fun toSnapshot(
        packageInfo: PackageInfo,
        enabledAccessibilityPackages: Set<String>,
        activeDeviceAdmins: Set<String>,
    ): AppSnapshot {
        val appInfo = requireNotNull(packageInfo.applicationInfo)
        val requestedPermissions = packageInfo.requestedPermissions?.toSet().orEmpty()
        val requestedFlags = packageInfo.requestedPermissionsFlags.orEmpty()

        val grantedPermissions = packageInfo.requestedPermissions
            ?.mapIndexedNotNull { index, permission ->
                val flag = requestedFlags.getOrNull(index) ?: 0
                permission.takeIf {
                    flag and PackageInfo.REQUESTED_PERMISSION_GRANTED != 0
                }
            }
            ?.toSet()
            .orEmpty()

        val services = packageInfo.services.orEmpty()
        val declaresAccessibility = services.any {
            it.permission == Manifest.permission.BIND_ACCESSIBILITY_SERVICE
        }
        val declaresNotificationListener = services.any {
            it.permission == "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"
        }
        val declaresVpn = services.any {
            it.permission == "android.permission.BIND_VPN_SERVICE"
        }

        val packageName = packageInfo.packageName
        return AppSnapshot(
            packageName = packageName,
            label = packageManager.getApplicationLabel(appInfo).toString(),
            versionName = packageInfo.versionName,
            installerPackage = installerPackage(packageName),
            firstInstallTimeEpochMs = packageInfo.firstInstallTime,
            lastUpdateTimeEpochMs = packageInfo.lastUpdateTime,
            certificateSha256 = signingCertificateSha256(packageInfo),
            apkSha256 = apkSha256(appInfo),
            requestedPermissions = requestedPermissions,
            grantedPermissions = grantedPermissions,
            isSystemApp = isSystemApp(appInfo),
            accessibilityEnabled = packageName in enabledAccessibilityPackages,
            deviceAdminActive = packageName in activeDeviceAdmins,
            declaresAccessibilityService = declaresAccessibility,
            declaresNotificationListener = declaresNotificationListener,
            declaresVpnService = declaresVpn,
        )
    }

    private fun enabledAccessibilityPackages(): Set<String> {
        val manager = context.getSystemService(AccessibilityManager::class.java)
        return manager
            ?.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            .orEmpty()
            .mapNotNull { it.resolveInfo?.serviceInfo?.packageName }
            .toSet()
    }

    private fun activeDeviceAdminPackages(): Set<String> {
        val manager = context.getSystemService(DevicePolicyManager::class.java)
        return manager?.activeAdmins.orEmpty().map { it.packageName }.toSet()
    }

    private fun installerPackage(packageName: String): String? = runCatching {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }
    }.getOrNull()

    private fun signingCertificateSha256(packageInfo: PackageInfo): String? = runCatching {
        val certificateBytes = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
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

        certificateBytes?.let(::sha256)
    }.getOrNull()

    private fun apkSha256(applicationInfo: ApplicationInfo): String? = runCatching {
        val sourceDir = applicationInfo.sourceDir ?: return@runCatching null
        sha256File(File(sourceDir))
    }.getOrNull()

    private fun isSystemApp(applicationInfo: ApplicationInfo): Boolean {
        val mask = ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP
        return applicationInfo.flags and mask != 0
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest
        .getInstance("SHA-256")
        .digest(bytes)
        .toHex()

    private fun sha256File(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().toHex()
    }

    private fun ByteArray.toHex(): String = joinToString(separator = "") { byte ->
        "%02x".format(byte)
    }
}
