package pl.siedlar.securityguardian.notifications

import android.Manifest
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.privacy.PrivacyAlertSink
import pl.siedlar.securityguardian.privacy.PrivacyAssessment

class AndroidPrivacyAlertSink(
    private val context: Context,
) : PrivacyAlertSink {

    init {
        ensureChannel()
    }

    override fun publish(assessment: PrivacyAssessment) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            return
        }

        val launchIntent = context.packageManager.getLaunchIntentForPackage(context.packageName)
        val pendingIntent = launchIntent?.let {
            PendingIntent.getActivity(
                context,
                assessment.snapshot.packageName.hashCode() xor PRIVACY_REQUEST_XOR,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }

        val title = when (assessment.riskLevel) {
            RiskLevel.CRITICAL -> "🔴 Krytyczny alert prywatności"
            RiskLevel.HIGH -> "🟠 Wysokie ryzyko prywatności"
            else -> "Alert prywatności"
        }

        val reason = assessment.evidence.firstOrNull()?.title ?: "Wykryto podwyższone ryzyko prywatności"
        val text = "${assessment.snapshot.label}: $reason. Ryzyko ${assessment.riskScore}/100."

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)

        if (pendingIntent != null) {
            builder.setContentIntent(pendingIntent)
            builder.addAction(0, "SPRAWDŹ", pendingIntent)
        }

        NotificationManagerCompat.from(context).notify(
            assessment.snapshot.packageName.hashCode() xor PRIVACY_NOTIFICATION_XOR,
            builder.build(),
        )
    }

    private fun ensureChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = context.getSystemService(NotificationManager::class.java)
        val channel = NotificationChannel(
            CHANNEL_ID,
            "Alerty prywatności",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Pilne alerty prywatności AI Security Guardian"
        }
        manager.createNotificationChannel(channel)
    }

    private companion object {
        const val CHANNEL_ID = "privacy_alerts"
        const val PRIVACY_REQUEST_XOR = 0x3456
        const val PRIVACY_NOTIFICATION_XOR = 0x6712
    }
}
