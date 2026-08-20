package pl.siedlar.securityguardian.inspector

import android.Manifest
import android.content.Context
import android.os.PowerManager
import androidx.core.app.NotificationManagerCompat
import pl.siedlar.securityguardian.privacy.ObservationState
import pl.siedlar.securityguardian.privacy.PrivacyInventorySource
import pl.siedlar.securityguardian.privacy.PrivacySnapshot

class AndroidPrivacyInspector(
    private val context: Context,
    private val appInspector: AndroidAppInspector = AndroidAppInspector(context),
) : PrivacyInventorySource {
    override fun collect(): List<PrivacySnapshot> {
        val enabledNotificationListeners = runCatching {
            NotificationManagerCompat.getEnabledListenerPackages(context)
        }.getOrDefault(emptySet())

        val powerManager = context.getSystemService(PowerManager::class.java)

        return appInspector.collect().map { app ->
            PrivacySnapshot(
                packageName = app.packageName,
                label = app.label,
                microphoneGranted = Manifest.permission.RECORD_AUDIO in app.grantedPermissions,
                cameraGranted = Manifest.permission.CAMERA in app.grantedPermissions,
                fineLocationGranted = Manifest.permission.ACCESS_FINE_LOCATION in app.grantedPermissions,
                backgroundLocationGranted = Manifest.permission.ACCESS_BACKGROUND_LOCATION in app.grantedPermissions,
                accessibilityEnabled = app.accessibilityEnabled,
                deviceAdminActive = app.deviceAdminActive,
                overlayCapabilityDeclared = Manifest.permission.SYSTEM_ALERT_WINDOW in app.requestedPermissions,
                notificationListenerDeclared = app.declaresNotificationListener,
                notificationListenerEnabled = app.packageName in enabledNotificationListeners,
                vpnServiceDeclared = app.declaresVpnService,
                batteryOptimizationExempt = runCatching {
                    powerManager?.isIgnoringBatteryOptimizations(app.packageName) == true
                }.getOrDefault(false),
                microphoneActiveState = ObservationState.UNKNOWN,
                cameraActiveState = ObservationState.UNKNOWN,
                screenCaptureState = ObservationState.UNKNOWN,
            )
        }
    }
}
