package pl.siedlar.securityguardian.network.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.DnsResolver
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.CancellationSignal
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

class AndroidSystemDnsForwarder(
    context: Context,
    private val timeoutMs: Long = 4_000L,
) {
    private val connectivityManager = context.applicationContext
        .getSystemService(ConnectivityManager::class.java)

    init {
        require(timeoutMs in 500L..15_000L)
    }

    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q

    fun forward(query: ByteArray): Result<ByteArray> {
        if (!isSupported()) {
            return Result.failure(UnsupportedOperationException("DNS Guard requires Android 10 / API 29 or newer"))
        }
        val network = selectUnderlyingNetwork()
            ?: return Result.failure(IllegalStateException("No validated non-VPN network available"))
        return rawQuery(network, query)
    }

    private fun selectUnderlyingNetwork(): Network? {
        val candidates = connectivityManager.allNetworks.mapNotNull { network ->
            val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return@mapNotNull null
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            if (!capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return@mapNotNull null
            val validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
            network to validated
        }
        return candidates
            .sortedByDescending { (_, validated) -> validated }
            .firstOrNull()
            ?.first
    }

    @Suppress("DEPRECATION")
    private fun rawQuery(network: Network, query: ByteArray): Result<ByteArray> {
        val latch = CountDownLatch(1)
        val answer = AtomicReference<ByteArray?>()
        val failure = AtomicReference<Throwable?>()
        val cancellation = CancellationSignal()
        val directExecutor = Executor { runnable -> runnable.run() }

        DnsResolver.getInstance().rawQuery(
            network,
            query,
            DnsResolver.FLAG_EMPTY,
            directExecutor,
            cancellation,
            object : DnsResolver.Callback<ByteArray> {
                override fun onAnswer(result: ByteArray, rcode: Int) {
                    answer.set(result)
                    latch.countDown()
                }

                override fun onError(error: DnsResolver.DnsException) {
                    failure.set(error)
                    latch.countDown()
                }
            },
        )

        if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
            cancellation.cancel()
            return Result.failure(IllegalStateException("System DNS query timed out"))
        }
        failure.get()?.let { return Result.failure(it) }
        val bytes = answer.get()
            ?: return Result.failure(IllegalStateException("System DNS returned no response bytes"))
        if (bytes.size < 12) {
            return Result.failure(IllegalStateException("System DNS response is shorter than DNS header"))
        }
        return Result.success(bytes)
    }
}
