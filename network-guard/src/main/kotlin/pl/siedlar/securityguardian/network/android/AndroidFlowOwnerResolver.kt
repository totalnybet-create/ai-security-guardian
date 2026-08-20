package pl.siedlar.securityguardian.network.android

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.Process
import android.system.OsConstants
import pl.siedlar.securityguardian.network.NetworkProtocol
import pl.siedlar.securityguardian.network.ParsedIpPacket
import java.net.InetAddress
import java.net.InetSocketAddress

data class FlowOwner(
    val uid: Int?,
    val packageName: String?,
    val ambiguous: Boolean,
)

class AndroidFlowOwnerResolver(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val connectivityManager = appContext.getSystemService(ConnectivityManager::class.java)
    private val packageManager = appContext.packageManager

    fun resolve(packet: ParsedIpPacket): FlowOwner {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return FlowOwner(uid = null, packageName = null, ambiguous = false)
        }
        val protocol = when (packet.protocol) {
            NetworkProtocol.TCP -> OsConstants.IPPROTO_TCP
            NetworkProtocol.UDP -> OsConstants.IPPROTO_UDP
            else -> return FlowOwner(uid = null, packageName = null, ambiguous = false)
        }
        val localIp = packet.sourceIp ?: return FlowOwner(null, null, false)
        val remoteIp = packet.destinationIp ?: return FlowOwner(null, null, false)
        val localPort = packet.sourcePort ?: return FlowOwner(null, null, false)
        val remotePort = packet.destinationPort ?: return FlowOwner(null, null, false)

        val uid = runCatching {
            connectivityManager.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(InetAddress.getByName(localIp), localPort),
                InetSocketAddress(InetAddress.getByName(remoteIp), remotePort),
            )
        }.getOrNull()?.takeIf { it != Process.INVALID_UID }
            ?: return FlowOwner(uid = null, packageName = null, ambiguous = false)

        val packages = packageManager.getPackagesForUid(uid)
            ?.distinct()
            .orEmpty()

        return when (packages.size) {
            1 -> FlowOwner(uid = uid, packageName = packages.single(), ambiguous = false)
            0 -> FlowOwner(uid = uid, packageName = null, ambiguous = false)
            else -> FlowOwner(uid = uid, packageName = null, ambiguous = true)
        }
    }
}
