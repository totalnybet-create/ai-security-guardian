package pl.siedlar.securityguardian.network

import java.net.InetAddress

enum class IpVersion { IPV4, IPV6 }

enum class PacketParseStatus {
    PARSED,
    FRAGMENT_WITHOUT_TRANSPORT_HEADER,
    UNSUPPORTED_PROTOCOL,
    MALFORMED,
    TRUNCATED,
}

data class ParsedIpPacket(
    val status: PacketParseStatus,
    val ipVersion: IpVersion?,
    val protocol: NetworkProtocol,
    val sourceIp: String?,
    val destinationIp: String?,
    val sourcePort: Int?,
    val destinationPort: Int?,
    val transportPayloadOffset: Int?,
    val transportPayloadLength: Int?,
    val fragmented: Boolean,
    val detail: String,
)

class IpPacketParser(
    private val maxIpv6ExtensionHeaders: Int = 8,
) {
    init {
        require(maxIpv6ExtensionHeaders in 1..32)
    }

    fun parse(packet: ByteArray, length: Int = packet.size): ParsedIpPacket {
        if (length < 0 || length > packet.size) {
            return malformed("Invalid packet length")
        }
        if (length == 0) return truncated("Empty packet")

        return when (u8(packet[0]) ushr 4) {
            4 -> parseIpv4(packet, length)
            6 -> parseIpv6(packet, length)
            else -> malformed("Unsupported IP version")
        }
    }

    private fun parseIpv4(packet: ByteArray, length: Int): ParsedIpPacket {
        if (length < IPV4_MIN_HEADER) return truncated("IPv4 header shorter than 20 bytes", IpVersion.IPV4)

        val ihlWords = u8(packet[0]) and 0x0F
        if (ihlWords < 5) return malformed("Invalid IPv4 IHL", IpVersion.IPV4)
        val headerLength = ihlWords * 4
        if (headerLength > length) return truncated("IPv4 options/header truncated", IpVersion.IPV4)

        val totalLength = u16(packet, 2)
        if (totalLength < headerLength) return malformed("IPv4 total length smaller than header", IpVersion.IPV4)
        if (totalLength > length) return truncated("IPv4 packet shorter than total length", IpVersion.IPV4)

        val flagsAndOffset = u16(packet, 6)
        val moreFragments = flagsAndOffset and 0x2000 != 0
        val fragmentOffset = flagsAndOffset and 0x1FFF
        val fragmented = moreFragments || fragmentOffset != 0

        val protocolNumber = u8(packet[9])
        val protocol = toProtocol(protocolNumber)
        val source = ip(packet.copyOfRange(12, 16))
        val destination = ip(packet.copyOfRange(16, 20))

        if (fragmentOffset != 0) {
            return ParsedIpPacket(
                status = PacketParseStatus.FRAGMENT_WITHOUT_TRANSPORT_HEADER,
                ipVersion = IpVersion.IPV4,
                protocol = protocol,
                sourceIp = source,
                destinationIp = destination,
                sourcePort = null,
                destinationPort = null,
                transportPayloadOffset = null,
                transportPayloadLength = null,
                fragmented = true,
                detail = "Non-initial IPv4 fragment has no transport header available.",
            )
        }

        return parseTransport(
            packet = packet,
            packetLength = totalLength,
            transportOffset = headerLength,
            protocolNumber = protocolNumber,
            ipVersion = IpVersion.IPV4,
            source = source,
            destination = destination,
            fragmented = fragmented,
        )
    }

    private fun parseIpv6(packet: ByteArray, length: Int): ParsedIpPacket {
        if (length < IPV6_HEADER) return truncated("IPv6 header shorter than 40 bytes", IpVersion.IPV6)

        val payloadLength = u16(packet, 4)
        if (payloadLength == 0) {
            return unsupported(
                detail = "IPv6 jumbograms are not parsed in the current bounded parser.",
                version = IpVersion.IPV6,
            )
        }
        val packetLength = IPV6_HEADER + payloadLength
        if (packetLength > length) return truncated("IPv6 payload truncated", IpVersion.IPV6)

        val source = ip(packet.copyOfRange(8, 24))
        val destination = ip(packet.copyOfRange(24, 40))
        var nextHeader = u8(packet[6])
        var offset = IPV6_HEADER
        var fragmented = false
        var fragmentOffset = 0
        var extensionCount = 0

        while (nextHeader in IPV6_EXTENSION_HEADERS) {
            extensionCount++
            if (extensionCount > maxIpv6ExtensionHeaders) {
                return malformed("Too many IPv6 extension headers", IpVersion.IPV6)
            }

            when (nextHeader) {
                IPV6_FRAGMENT -> {
                    if (offset + 8 > packetLength) return truncated("IPv6 fragment header truncated", IpVersion.IPV6)
                    val next = u8(packet[offset])
                    val fragmentField = u16(packet, offset + 2)
                    fragmentOffset = (fragmentField and 0xFFF8) ushr 3
                    fragmented = true
                    nextHeader = next
                    offset += 8
                }

                IPV6_AUTHENTICATION -> {
                    if (offset + 2 > packetLength) return truncated("IPv6 AH header truncated", IpVersion.IPV6)
                    val next = u8(packet[offset])
                    val lengthWords = u8(packet[offset + 1])
                    val headerLength = (lengthWords + 2) * 4
                    if (headerLength < 8 || offset + headerLength > packetLength) {
                        return truncated("IPv6 AH length invalid/truncated", IpVersion.IPV6)
                    }
                    nextHeader = next
                    offset += headerLength
                }

                IPV6_ESP -> {
                    return unsupported(
                        detail = "ESP payload cannot be inspected without decryption.",
                        version = IpVersion.IPV6,
                        protocol = NetworkProtocol.OTHER,
                        source = source,
                        destination = destination,
                        fragmented = fragmented,
                    )
                }

                else -> {
                    if (offset + 2 > packetLength) return truncated("IPv6 extension header truncated", IpVersion.IPV6)
                    val next = u8(packet[offset])
                    val hdrExtLen = u8(packet[offset + 1])
                    val headerLength = (hdrExtLen + 1) * 8
                    if (headerLength < 8 || offset + headerLength > packetLength) {
                        return truncated("IPv6 extension length invalid/truncated", IpVersion.IPV6)
                    }
                    nextHeader = next
                    offset += headerLength
                }
            }
        }

        if (fragmented && fragmentOffset != 0) {
            return ParsedIpPacket(
                status = PacketParseStatus.FRAGMENT_WITHOUT_TRANSPORT_HEADER,
                ipVersion = IpVersion.IPV6,
                protocol = toProtocol(nextHeader),
                sourceIp = source,
                destinationIp = destination,
                sourcePort = null,
                destinationPort = null,
                transportPayloadOffset = null,
                transportPayloadLength = null,
                fragmented = true,
                detail = "Non-initial IPv6 fragment has no transport header available.",
            )
        }

        return parseTransport(
            packet = packet,
            packetLength = packetLength,
            transportOffset = offset,
            protocolNumber = nextHeader,
            ipVersion = IpVersion.IPV6,
            source = source,
            destination = destination,
            fragmented = fragmented,
        )
    }

    private fun parseTransport(
        packet: ByteArray,
        packetLength: Int,
        transportOffset: Int,
        protocolNumber: Int,
        ipVersion: IpVersion,
        source: String,
        destination: String,
        fragmented: Boolean,
    ): ParsedIpPacket {
        return when (protocolNumber) {
            IPPROTO_TCP -> parseTcp(packet, packetLength, transportOffset, ipVersion, source, destination, fragmented)
            IPPROTO_UDP -> parseUdp(packet, packetLength, transportOffset, ipVersion, source, destination, fragmented)
            IPPROTO_ICMP, IPPROTO_ICMPV6 -> ParsedIpPacket(
                status = PacketParseStatus.PARSED,
                ipVersion = ipVersion,
                protocol = NetworkProtocol.ICMP,
                sourceIp = source,
                destinationIp = destination,
                sourcePort = null,
                destinationPort = null,
                transportPayloadOffset = transportOffset,
                transportPayloadLength = (packetLength - transportOffset).coerceAtLeast(0),
                fragmented = fragmented,
                detail = "ICMP packet parsed at IP layer.",
            )

            else -> unsupported(
                detail = "IP protocol $protocolNumber is not handled by transport parser.",
                version = ipVersion,
                protocol = NetworkProtocol.OTHER,
                source = source,
                destination = destination,
                fragmented = fragmented,
            )
        }
    }

    private fun parseTcp(
        packet: ByteArray,
        packetLength: Int,
        offset: Int,
        version: IpVersion,
        source: String,
        destination: String,
        fragmented: Boolean,
    ): ParsedIpPacket {
        if (offset + TCP_MIN_HEADER > packetLength) return truncated("TCP header truncated", version)
        val sourcePort = u16(packet, offset)
        val destinationPort = u16(packet, offset + 2)
        val dataOffsetWords = u8(packet[offset + 12]) ushr 4
        if (dataOffsetWords < 5) return malformed("Invalid TCP data offset", version)
        val headerLength = dataOffsetWords * 4
        if (offset + headerLength > packetLength) return truncated("TCP options/header truncated", version)

        return ParsedIpPacket(
            status = PacketParseStatus.PARSED,
            ipVersion = version,
            protocol = NetworkProtocol.TCP,
            sourceIp = source,
            destinationIp = destination,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            transportPayloadOffset = offset + headerLength,
            transportPayloadLength = packetLength - (offset + headerLength),
            fragmented = fragmented,
            detail = "TCP packet parsed.",
        )
    }

    private fun parseUdp(
        packet: ByteArray,
        packetLength: Int,
        offset: Int,
        version: IpVersion,
        source: String,
        destination: String,
        fragmented: Boolean,
    ): ParsedIpPacket {
        if (offset + UDP_HEADER > packetLength) return truncated("UDP header truncated", version)
        val sourcePort = u16(packet, offset)
        val destinationPort = u16(packet, offset + 2)
        val udpLength = u16(packet, offset + 4)
        if (udpLength < UDP_HEADER) return malformed("Invalid UDP length", version)
        if (offset + udpLength > packetLength) return truncated("UDP payload truncated", version)

        return ParsedIpPacket(
            status = PacketParseStatus.PARSED,
            ipVersion = version,
            protocol = NetworkProtocol.UDP,
            sourceIp = source,
            destinationIp = destination,
            sourcePort = sourcePort,
            destinationPort = destinationPort,
            transportPayloadOffset = offset + UDP_HEADER,
            transportPayloadLength = udpLength - UDP_HEADER,
            fragmented = fragmented,
            detail = "UDP packet parsed.",
        )
    }

    private fun toProtocol(protocol: Int): NetworkProtocol = when (protocol) {
        IPPROTO_TCP -> NetworkProtocol.TCP
        IPPROTO_UDP -> NetworkProtocol.UDP
        IPPROTO_ICMP, IPPROTO_ICMPV6 -> NetworkProtocol.ICMP
        else -> NetworkProtocol.OTHER
    }

    private fun malformed(detail: String, version: IpVersion? = null) = ParsedIpPacket(
        PacketParseStatus.MALFORMED, version, NetworkProtocol.OTHER, null, null, null, null, null, null, false, detail,
    )

    private fun truncated(detail: String, version: IpVersion? = null) = ParsedIpPacket(
        PacketParseStatus.TRUNCATED, version, NetworkProtocol.OTHER, null, null, null, null, null, null, false, detail,
    )

    private fun unsupported(
        detail: String,
        version: IpVersion? = null,
        protocol: NetworkProtocol = NetworkProtocol.OTHER,
        source: String? = null,
        destination: String? = null,
        fragmented: Boolean = false,
    ) = ParsedIpPacket(
        PacketParseStatus.UNSUPPORTED_PROTOCOL,
        version,
        protocol,
        source,
        destination,
        null,
        null,
        null,
        null,
        fragmented,
        detail,
    )

    private fun u8(value: Byte): Int = value.toInt() and 0xFF
    private fun u16(data: ByteArray, offset: Int): Int = (u8(data[offset]) shl 8) or u8(data[offset + 1])
    private fun ip(bytes: ByteArray): String = InetAddress.getByAddress(bytes).hostAddress

    private companion object {
        const val IPV4_MIN_HEADER = 20
        const val IPV6_HEADER = 40
        const val TCP_MIN_HEADER = 20
        const val UDP_HEADER = 8

        const val IPPROTO_ICMP = 1
        const val IPPROTO_TCP = 6
        const val IPPROTO_UDP = 17
        const val IPPROTO_ICMPV6 = 58

        const val IPV6_HOP_BY_HOP = 0
        const val IPV6_ROUTING = 43
        const val IPV6_FRAGMENT = 44
        const val IPV6_ESP = 50
        const val IPV6_AUTHENTICATION = 51
        const val IPV6_DESTINATION_OPTIONS = 60
        val IPV6_EXTENSION_HEADERS = setOf(
            IPV6_HOP_BY_HOP,
            IPV6_ROUTING,
            IPV6_FRAGMENT,
            IPV6_ESP,
            IPV6_AUTHENTICATION,
            IPV6_DESTINATION_OPTIONS,
        )
    }
}
