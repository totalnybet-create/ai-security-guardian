package pl.siedlar.securityguardian.network.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import pl.siedlar.securityguardian.audit.JsonlAuditLogger
import pl.siedlar.securityguardian.core.AuditEvent
import pl.siedlar.securityguardian.core.RiskLevel
import pl.siedlar.securityguardian.network.DnsMessageParser
import pl.siedlar.securityguardian.network.DnsResponseFactory
import pl.siedlar.securityguardian.network.IpPacketParser
import pl.siedlar.securityguardian.network.NetworkAction
import pl.siedlar.securityguardian.network.NetworkPolicyEngine
import pl.siedlar.securityguardian.network.NetworkProtocol
import pl.siedlar.securityguardian.network.PacketFlowExtractor
import pl.siedlar.securityguardian.network.PacketParseStatus
import pl.siedlar.securityguardian.network.UdpIpResponseBuilder
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

class GuardianDnsVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    private val writeLock = Any()
    private var tun: ParcelFileDescriptor? = null
    private var input: FileInputStream? = null
    private var output: FileOutputStream? = null
    private var readerExecutor: ExecutorService? = null
    private var workers: ExecutorService? = null

    private val packetParser by lazy { IpPacketParser() }
    private val dnsParser by lazy { DnsMessageParser() }
    private val flowExtractor by lazy { PacketFlowExtractor(packetParser, dnsParser) }
    private val policyEngine by lazy { NetworkPolicyEngine() }
    private val ruleStore by lazy { AndroidNetworkRuleStore(applicationContext) }
    private val ownerResolver by lazy { AndroidFlowOwnerResolver(applicationContext) }
    private val dnsForwarder by lazy { AndroidSystemDnsForwarder(applicationContext) }
    private val dnsResponseFactory by lazy { DnsResponseFactory(dnsParser) }
    private val responseBuilder by lazy { UdpIpResponseBuilder() }
    private val audit by lazy { JsonlAuditLogger(applicationContext) }
    private val statusStore by lazy { DnsGuardStatusStore(applicationContext) }

    override fun onCreate() {
        super.onCreate()
        ensureNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopDnsGuard("Stopped by user")
            return START_NOT_STICKY
        }

        startForeground(NOTIFICATION_ID, foregroundNotification("Uruchamianie ochrony DNS…"))
        if (running.compareAndSet(false, true)) {
            statusStore.write(DnsGuardState.STARTING, "Creating DNS-only VPN interface")
            readerExecutor = Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "guardian-dns-tun").apply { isDaemon = true }
            }
            workers = Executors.newFixedThreadPool(4) { runnable ->
                Thread(runnable, "guardian-dns-worker").apply { isDaemon = true }
            }
            readerExecutor?.execute(::runTunnel)
        }
        return START_STICKY
    }

    override fun onRevoke() {
        stopDnsGuard("VPN permission revoked")
        super.onRevoke()
    }

    override fun onDestroy() {
        closeResources()
        if (statusStore.read().state != DnsGuardState.ERROR) {
            statusStore.write(DnsGuardState.STOPPED, "DNS Guard stopped")
        }
        super.onDestroy()
    }

    private fun runTunnel() {
        try {
            check(Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                "DNS Guard requires Android 10 / API 29 or newer"
            }
            check(VpnService.prepare(this) == null) {
                "VPN consent is not active"
            }
            check(dnsForwarder.isSupported()) {
                "System DNS raw-query forwarding is unavailable"
            }

            val descriptor = Builder()
                .setSession("AI Security Guardian · DNS Guard")
                .addAddress(CLIENT_IPV4, 32)
                .addDnsServer(VIRTUAL_DNS_IPV4)
                .addRoute(VIRTUAL_DNS_IPV4, 32)
                .setMtu(1500)
                .setBlocking(true)
                .establish()
                ?: error("Android refused to establish VPN interface")

            tun = descriptor
            input = FileInputStream(descriptor.fileDescriptor)
            output = FileOutputStream(descriptor.fileDescriptor)
            statusStore.write(
                DnsGuardState.RUNNING_DNS_ONLY,
                "DNS-only enforcement active; non-DNS traffic is not routed through Guardian",
            )
            updateForegroundNotification("Ochrona DNS aktywna · tryb DNS-only")
            auditEvent(
                event = "DNS_GUARD_STARTED",
                source = "network-guard",
                risk = RiskLevel.SAFE,
                action = "START",
                result = "RUNNING_DNS_ONLY",
                evidence = listOf("virtual_dns=$VIRTUAL_DNS_IPV4"),
                verification = "VpnService TUN established with only virtual DNS /32 route",
            )

            val buffer = ByteArray(MAX_PACKET_SIZE)
            while (running.get()) {
                val count = input?.read(buffer) ?: break
                if (count <= 0) continue
                val packet = buffer.copyOf(count)
                workers?.execute { processDnsPacket(packet) }
            }
        } catch (error: Throwable) {
            if (running.get()) {
                statusStore.write(DnsGuardState.ERROR, error.message ?: error::class.java.simpleName)
                auditEvent(
                    event = "DNS_GUARD_FAILED",
                    source = "network-guard",
                    risk = RiskLevel.MEDIUM,
                    action = "START_OR_READ",
                    result = "FAILED",
                    evidence = listOf(error::class.java.simpleName),
                    verification = "No protected-state claim emitted",
                )
            }
        } finally {
            running.set(false)
            closeResources()
            stopSelf()
        }
    }

    private fun processDnsPacket(packetBytes: ByteArray) {
        try {
            val parsed = packetParser.parse(packetBytes)
            if (
                parsed.status != PacketParseStatus.PARSED ||
                parsed.protocol != NetworkProtocol.UDP ||
                parsed.destinationPort != DNS_PORT ||
                parsed.destinationIp != VIRTUAL_DNS_IPV4
            ) {
                auditEvent(
                    event = "DNS_GUARD_UNEXPECTED_PACKET",
                    source = parsed.destinationIp ?: "unknown",
                    risk = RiskLevel.LOW,
                    action = "DROP_OUTSIDE_DNS_ROUTE",
                    result = parsed.status.name,
                    evidence = listOf(parsed.detail),
                    verification = "Packet was not described as successfully filtered DNS",
                )
                return
            }

            val owner = ownerResolver.resolve(parsed)
            val observation = flowExtractor.observe(
                packetBytes = packetBytes,
                appPackage = owner.packageName,
            )
            val dns = observation.dns ?: return auditMalformedDns(parsed.destinationIp)
            if (dns.isResponse || dns.questions.isEmpty()) return auditMalformedDns(parsed.destinationIp)
            val flow = observation.flow ?: return auditMalformedDns(parsed.destinationIp)
            val payloadOffset = parsed.transportPayloadOffset ?: return auditMalformedDns(parsed.destinationIp)
            val payloadLength = parsed.transportPayloadLength ?: return auditMalformedDns(parsed.destinationIp)
            if (payloadOffset < 0 || payloadLength < 0 || payloadOffset + payloadLength > packetBytes.size) {
                return auditMalformedDns(parsed.destinationIp)
            }
            val query = packetBytes.copyOfRange(payloadOffset, payloadOffset + payloadLength)

            val decision = policyEngine.decide(
                flow = flow,
                rules = ruleStore.list(),
                threatEvidence = emptyList(),
                nowEpochMs = System.currentTimeMillis(),
            )

            val responsePayload: ByteArray
            val result: String
            when (decision.action) {
                NetworkAction.BLOCK -> {
                    responsePayload = dnsResponseFactory.nxdomain(query)
                        ?: dnsResponseFactory.serverFailure(query)
                        ?: return auditMalformedDns(parsed.destinationIp)
                    result = "NXDOMAIN"
                }

                NetworkAction.ALLOW,
                NetworkAction.TEMPORARY_ALLOW,
                NetworkAction.ASK,
                -> {
                    val upstream = dnsForwarder.forward(query).getOrNull()
                    val validUpstream = upstream?.takeIf { answer ->
                        val metadata = dnsParser.parseUdpPayload(answer)
                        metadata != null && metadata.isResponse && metadata.id == dns.id
                    }
                    responsePayload = validUpstream
                        ?: dnsResponseFactory.serverFailure(query)
                        ?: return auditMalformedDns(parsed.destinationIp)
                    result = if (validUpstream != null) "FORWARDED" else "SERVFAIL"
                }
            }

            val responsePacket = responseBuilder.buildResponse(packetBytes, parsed, responsePayload)
                ?: error("Could not build UDP/IP DNS response")
            synchronized(writeLock) {
                output?.write(responsePacket) ?: error("TUN output is unavailable")
            }

            val domain = dns.questions.first().name
            val risk = if (decision.action == NetworkAction.BLOCK) RiskLevel.LOW else RiskLevel.SAFE
            auditEvent(
                event = if (decision.action == NetworkAction.BLOCK) "NETWORK_DNS_BLOCKED" else "NETWORK_DNS_RESOLVED",
                source = domain,
                risk = risk,
                action = decision.action.name,
                result = result,
                evidence = listOfNotNull(
                    "domain=$domain",
                    owner.uid?.let { "uid=$it" },
                    owner.packageName?.let { "package=$it" },
                    "owner_ambiguous=${owner.ambiguous}",
                    decision.matchedRuleId?.let { "rule=$it" },
                ),
                verification = "DNS response packet was generated and written to TUN",
            )
        } catch (error: Throwable) {
            auditEvent(
                event = "DNS_GUARD_PACKET_FAILED",
                source = "network-guard",
                risk = RiskLevel.LOW,
                action = "PROCESS_DNS_PACKET",
                result = "FAILED",
                evidence = listOf(error.message ?: error::class.java.simpleName),
                verification = "No successful enforcement claim emitted",
            )
        }
    }

    private fun auditMalformedDns(destination: String?) {
        auditEvent(
            event = "DNS_GUARD_MALFORMED_DNS",
            source = destination ?: "unknown",
            risk = RiskLevel.LOW,
            action = "PARSE_DNS",
            result = "REJECTED",
            evidence = emptyList(),
            verification = "No DNS verdict emitted for malformed payload",
        )
    }

    private fun stopDnsGuard(detail: String) {
        running.set(false)
        closeResources()
        statusStore.write(DnsGuardState.STOPPED, detail)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeResources() {
        runCatching { input?.close() }
        runCatching { output?.close() }
        runCatching { tun?.close() }
        input = null
        output = null
        tun = null
        workers?.shutdownNow()
        readerExecutor?.shutdownNow()
        workers = null
        readerExecutor = null
    }

    private fun auditEvent(
        event: String,
        source: String,
        risk: RiskLevel,
        action: String,
        result: String,
        evidence: List<String>,
        verification: String,
    ) {
        audit.append(
            AuditEvent(
                timestampEpochMs = System.currentTimeMillis(),
                event = event,
                source = source,
                risk = risk,
                evidence = evidence,
                action = action,
                result = result,
                verification = verification,
            ),
        )
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                "Ochrona sieci DNS",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Stały status lokalnej ochrony DNS AI Security Guardian"
            },
        )
    }

    private fun foregroundNotification(text: String): android.app.Notification {
        val launchIntent = packageManager.getLaunchIntentForPackage(packageName)
        val pendingIntent = launchIntent?.let {
            PendingIntent.getActivity(
                this,
                0,
                it,
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
        }
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("AI Security Guardian · DNS Guard")
            .setContentText(text)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .apply { if (pendingIntent != null) setContentIntent(pendingIntent) }
            .build()
    }

    private fun updateForegroundNotification(text: String) {
        getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, foregroundNotification(text))
    }

    companion object {
        const val ACTION_START = "pl.siedlar.securityguardian.network.START_DNS_GUARD"
        const val ACTION_STOP = "pl.siedlar.securityguardian.network.STOP_DNS_GUARD"
        private const val CHANNEL_ID = "dns_guard_status"
        private const val NOTIFICATION_ID = 3201
        private const val CLIENT_IPV4 = "10.77.0.1"
        private const val VIRTUAL_DNS_IPV4 = "10.77.0.2"
        private const val DNS_PORT = 53
        private const val MAX_PACKET_SIZE = 65_535
    }
}
