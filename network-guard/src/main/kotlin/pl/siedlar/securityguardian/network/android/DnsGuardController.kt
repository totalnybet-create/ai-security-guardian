package pl.siedlar.securityguardian.network.android

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.content.ContextCompat

enum class DnsGuardState {
    STOPPED,
    STARTING,
    RUNNING_DNS_ONLY,
    ERROR,
    UNSUPPORTED,
}

data class DnsGuardStatus(
    val state: DnsGuardState,
    val detail: String?,
    val updatedAtEpochMs: Long,
)

class DnsGuardController(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val statusStore = DnsGuardStatusStore(appContext)

    fun prepareIntent(): Intent? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        return VpnService.prepare(appContext)
    }

    fun start(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            statusStore.write(DnsGuardState.UNSUPPORTED, "DNS Guard requires Android 10 / API 29 or newer")
            return false
        }
        if (VpnService.prepare(appContext) != null) {
            statusStore.write(DnsGuardState.STOPPED, "VPN consent is required")
            return false
        }
        statusStore.write(DnsGuardState.STARTING, "Preparing DNS-only VPN")
        ContextCompat.startForegroundService(
            appContext,
            Intent(appContext, GuardianDnsVpnService::class.java)
                .setAction(GuardianDnsVpnService.ACTION_START),
        )
        return true
    }

    fun stop(): Boolean = appContext.stopService(
        Intent(appContext, GuardianDnsVpnService::class.java),
    )

    fun status(): DnsGuardStatus = statusStore.read()
}

internal class DnsGuardStatusStore(
    @Suppress("UNUSED_PARAMETER") context: Context,
) {
    fun write(state: DnsGuardState, detail: String?) {
        val now = System.currentTimeMillis()
        liveState = state
        liveDetail = detail
        liveUpdatedAt = now
    }

    fun read(): DnsGuardStatus {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return DnsGuardStatus(
                state = DnsGuardState.UNSUPPORTED,
                detail = "DNS Guard requires Android 10 / API 29 or newer",
                updatedAtEpochMs = System.currentTimeMillis(),
            )
        }
        return DnsGuardStatus(
            state = liveState,
            detail = liveDetail,
            updatedAtEpochMs = liveUpdatedAt,
        )
    }

    private companion object {
        @Volatile
        var liveState: DnsGuardState = DnsGuardState.STOPPED

        @Volatile
        var liveDetail: String? = null

        @Volatile
        var liveUpdatedAt: Long = 0L
    }
}
