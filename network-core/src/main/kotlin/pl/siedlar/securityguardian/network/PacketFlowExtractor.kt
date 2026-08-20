package pl.siedlar.securityguardian.network

data class PacketFlowObservation(
    val packet: ParsedIpPacket,
    val flow: NetworkFlow?,
    val dns: DnsMessageMetadata?,
)

class PacketFlowExtractor(
    private val packetParser: IpPacketParser = IpPacketParser(),
    private val dnsParser: DnsMessageParser = DnsMessageParser(),
) {
    fun observe(
        packetBytes: ByteArray,
        length: Int = packetBytes.size,
        appPackage: String? = null,
    ): PacketFlowObservation {
        val packet = packetParser.parse(packetBytes, length)
        if (packet.status != PacketParseStatus.PARSED) {
            return PacketFlowObservation(packet, flow = null, dns = null)
        }

        val dns = parseDnsIfAvailable(packetBytes, packet)
        val destinationHost = dns
            ?.takeIf { !it.isResponse }
            ?.questions
            ?.firstOrNull()
            ?.name

        val flow = NetworkFlow(
            appPackage = appPackage,
            destinationHost = destinationHost,
            destinationIp = packet.destinationIp,
            destinationPort = packet.destinationPort,
            protocol = packet.protocol,
        )

        return PacketFlowObservation(
            packet = packet,
            flow = flow,
            dns = dns,
        )
    }

    private fun parseDnsIfAvailable(
        bytes: ByteArray,
        packet: ParsedIpPacket,
    ): DnsMessageMetadata? {
        if (packet.protocol != NetworkProtocol.UDP) return null
        if (packet.destinationPort != DNS_PORT && packet.sourcePort != DNS_PORT) return null
        val offset = packet.transportPayloadOffset ?: return null
        val length = packet.transportPayloadLength ?: return null
        return dnsParser.parseUdpPayload(bytes, offset, length)
    }

    private companion object {
        const val DNS_PORT = 53
    }
}
