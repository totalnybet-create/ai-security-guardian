package pl.siedlar.securityguardian.network

class UdpIpResponseBuilder {
    fun buildResponse(
        requestPacket: ByteArray,
        parsedRequest: ParsedIpPacket,
        udpPayload: ByteArray,
    ): ByteArray? {
        if (parsedRequest.status != PacketParseStatus.PARSED) return null
        if (parsedRequest.protocol != NetworkProtocol.UDP) return null
        val sourcePort = parsedRequest.sourcePort ?: return null
        val destinationPort = parsedRequest.destinationPort ?: return null

        return when (parsedRequest.ipVersion) {
            IpVersion.IPV4 -> buildIpv4(requestPacket, sourcePort, destinationPort, udpPayload)
            IpVersion.IPV6 -> buildIpv6(requestPacket, sourcePort, destinationPort, udpPayload)
            null -> null
        }
    }

    private fun buildIpv4(
        request: ByteArray,
        clientPort: Int,
        serverPort: Int,
        payload: ByteArray,
    ): ByteArray? {
        if (request.size < IPV4_HEADER) return null
        val udpLength = UDP_HEADER + payload.size
        val totalLength = IPV4_HEADER + udpLength
        if (totalLength > 0xFFFF) return null

        val response = ByteArray(totalLength)
        response[0] = 0x45
        response[1] = 0
        put16(response, 2, totalLength)
        put16(response, 4, 0)
        put16(response, 6, 0)
        response[8] = 64
        response[9] = IPPROTO_UDP.toByte()
        request.copyInto(response, destinationOffset = 12, startIndex = 16, endIndex = 20)
        request.copyInto(response, destinationOffset = 16, startIndex = 12, endIndex = 16)
        put16(response, 20, serverPort)
        put16(response, 22, clientPort)
        put16(response, 24, udpLength)
        put16(response, 26, 0)
        payload.copyInto(response, 28)

        put16(response, 10, internetChecksum(response, 0, IPV4_HEADER))
        val udpChecksum = udpChecksumIpv4(response, 12, 16, 20, udpLength)
        put16(response, 26, if (udpChecksum == 0) 0xFFFF else udpChecksum)
        return response
    }

    private fun buildIpv6(
        request: ByteArray,
        clientPort: Int,
        serverPort: Int,
        payload: ByteArray,
    ): ByteArray? {
        if (request.size < IPV6_HEADER) return null
        val udpLength = UDP_HEADER + payload.size
        if (udpLength > 0xFFFF) return null
        val response = ByteArray(IPV6_HEADER + udpLength)
        response[0] = 0x60
        put16(response, 4, udpLength)
        response[6] = IPPROTO_UDP.toByte()
        response[7] = 64
        request.copyInto(response, destinationOffset = 8, startIndex = 24, endIndex = 40)
        request.copyInto(response, destinationOffset = 24, startIndex = 8, endIndex = 24)
        put16(response, 40, serverPort)
        put16(response, 42, clientPort)
        put16(response, 44, udpLength)
        put16(response, 46, 0)
        payload.copyInto(response, 48)

        val checksum = udpChecksumIpv6(response, 8, 24, 40, udpLength)
        put16(response, 46, if (checksum == 0) 0xFFFF else checksum)
        return response
    }

    private fun udpChecksumIpv4(
        packet: ByteArray,
        sourceOffset: Int,
        destinationOffset: Int,
        udpOffset: Int,
        udpLength: Int,
    ): Int {
        var sum = 0L
        sum = addWords(sum, packet, sourceOffset, 4)
        sum = addWords(sum, packet, destinationOffset, 4)
        sum += IPPROTO_UDP.toLong()
        sum += udpLength.toLong()
        sum = addWords(sum, packet, udpOffset, udpLength)
        return finishChecksum(sum)
    }

    private fun udpChecksumIpv6(
        packet: ByteArray,
        sourceOffset: Int,
        destinationOffset: Int,
        udpOffset: Int,
        udpLength: Int,
    ): Int {
        var sum = 0L
        sum = addWords(sum, packet, sourceOffset, 16)
        sum = addWords(sum, packet, destinationOffset, 16)
        sum += (udpLength ushr 16).toLong()
        sum += (udpLength and 0xFFFF).toLong()
        sum += IPPROTO_UDP.toLong()
        sum = addWords(sum, packet, udpOffset, udpLength)
        return finishChecksum(sum)
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
        return finishChecksum(addWords(0L, data, offset, length))
    }

    private fun addWords(initial: Long, data: ByteArray, offset: Int, length: Int): Long {
        var sum = initial
        var cursor = offset
        val end = offset + length
        while (cursor + 1 < end) {
            sum += ((u8(data[cursor]) shl 8) or u8(data[cursor + 1])).toLong()
            cursor += 2
        }
        if (cursor < end) sum += (u8(data[cursor]) shl 8).toLong()
        return sum
    }

    private fun finishChecksum(initial: Long): Int {
        var sum = initial
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.inv().toInt() and 0xFFFF
    }

    private fun u8(value: Byte): Int = value.toInt() and 0xFF
    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private companion object {
        const val IPV4_HEADER = 20
        const val IPV6_HEADER = 40
        const val UDP_HEADER = 8
        const val IPPROTO_UDP = 17
    }
}
