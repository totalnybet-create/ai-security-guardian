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

internal class DnsGuardStatusStore(context: Context) {
    private val preferences = context.getSharedPreferences("dns-guard-status-v1", Context.MODE_PRIVATE)

    fun write(state: DnsGuardState, detail: String?) {
        preferences.edit()
            .putString(KEY_STATE, state.name)
            .putString(KEY_DETAIL, detail)
            .putLong(KEY_UPDATED_AT, System.currentTimeMillis())
            .apply()
    }

    fun read(): DnsGuardStatus {
        val state = preferences.getString(KEY_STATE, null)
            ?.let { runCatching { DnsGuardState.valueOf(it) }.getOrNull() }
            ?: if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) DnsGuardState.UNSUPPORTED else DnsGuardState.STOPPED
        return DnsGuardStatus(
            state = state,
            detail = preferences.getString(KEY_DETAIL, null),
            updatedAtEpochMs = preferences.getLong(KEY_UPDATED_AT, 0L),
        )
    }

    private companion object {
        const val KEY_STATE = "state"
        const val KEY_DETAIL = "detail"
        const val KEY_UPDATED_AT = "updatedAt"
    }
}
