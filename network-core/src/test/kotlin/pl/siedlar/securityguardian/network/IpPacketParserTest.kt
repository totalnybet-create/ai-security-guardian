package pl.siedlar.securityguardian.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class IpPacketParserTest {
    private val parser = IpPacketParser()

    @Test
    fun parsesIpv4UdpAndPayloadBounds() {
        val payload = byteArrayOf(1, 2, 3, 4)
        val packet = ipv4Udp(
            source = byteArrayOf(10, 0, 0, 2),
            destination = byteArrayOf(8, 8, 8, 8),
            sourcePort = 53000,
            destinationPort = 53,
            payload = payload,
        )

        val result = parser.parse(packet)
        assertEquals(PacketParseStatus.PARSED, result.status)
        assertEquals(IpVersion.IPV4, result.ipVersion)
        assertEquals(NetworkProtocol.UDP, result.protocol)
        assertEquals("10.0.0.2", result.sourceIp)
        assertEquals("8.8.8.8", result.destinationIp)
        assertEquals(53000, result.sourcePort)
        assertEquals(53, result.destinationPort)
        assertEquals(payload.size, result.transportPayloadLength)
    }

    @Test
    fun parsesIpv6WithHopByHopExtension() {
        val payload = byteArrayOf(9, 8, 7)
        val packet = ipv6UdpWithHopByHop(
            sourcePort = 12345,
            destinationPort = 443,
            payload = payload,
        )

        val result = parser.parse(packet)
        assertEquals(PacketParseStatus.PARSED, result.status)
        assertEquals(IpVersion.IPV6, result.ipVersion)
        assertEquals(NetworkProtocol.UDP, result.protocol)
        assertEquals(12345, result.sourcePort)
        assertEquals(443, result.destinationPort)
        assertEquals(payload.size, result.transportPayloadLength)
        assertTrue(result.destinationIp?.contains("2001:db8") == true)
    }

    @Test
    fun nonInitialIpv4FragmentDoesNotInventPorts() {
        val packet = ipv4Udp(
            source = byteArrayOf(10, 0, 0, 2),
            destination = byteArrayOf(1, 1, 1, 1),
            sourcePort = 50000,
            destinationPort = 53,
            payload = byteArrayOf(1, 2),
        )
        packet[6] = 0x00
        packet[7] = 0x01

        val result = parser.parse(packet)
        assertEquals(PacketParseStatus.FRAGMENT_WITHOUT_TRANSPORT_HEADER, result.status)
        assertTrue(result.fragmented)
        assertNull(result.sourcePort)
        assertNull(result.destinationPort)
    }

    @Test
    fun truncatedTotalLengthIsRejected() {
        val packet = ipv4Udp(
            source = byteArrayOf(10, 0, 0, 2),
            destination = byteArrayOf(8, 8, 8, 8),
            sourcePort = 1,
            destinationPort = 2,
            payload = byteArrayOf(1, 2, 3),
        )
        packet[2] = 0x7F
        packet[3] = 0xFF.toByte()

        val result = parser.parse(packet)
        assertEquals(PacketParseStatus.TRUNCATED, result.status)
    }

    @Test
    fun malformedTcpDataOffsetIsRejected() {
        val packet = ByteArray(40)
        packet[0] = 0x45
        put16(packet, 2, 40)
        packet[9] = 6
        packet[12] = 10
        packet[16] = 8
        packet[17] = 8
        packet[18] = 8
        packet[19] = 8
        put16(packet, 20, 1234)
        put16(packet, 22, 443)
        packet[32] = 0x40

        val result = parser.parse(packet)
        assertEquals(PacketParseStatus.MALFORMED, result.status)
    }

    private fun ipv4Udp(
        source: ByteArray,
        destination: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val udpLength = 8 + payload.size
        val total = 20 + udpLength
        return ByteArray(total).also { packet ->
            packet[0] = 0x45
            put16(packet, 2, total)
            packet[8] = 64
            packet[9] = 17
            source.copyInto(packet, 12)
            destination.copyInto(packet, 16)
            put16(packet, 20, sourcePort)
            put16(packet, 22, destinationPort)
            put16(packet, 24, udpLength)
            payload.copyInto(packet, 28)
        }
    }

    private fun ipv6UdpWithHopByHop(
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val extensionLength = 8
        val udpLength = 8 + payload.size
        val payloadLength = extensionLength + udpLength
        return ByteArray(40 + payloadLength).also { packet ->
            packet[0] = 0x60
            put16(packet, 4, payloadLength)
            packet[6] = 0
            packet[7] = 64
            byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1).copyInto(packet, 8)
            byteArrayOf(0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2).copyInto(packet, 24)
            packet[40] = 17
            packet[41] = 0
            val udp = 48
            put16(packet, udp, sourcePort)
            put16(packet, udp + 2, destinationPort)
            put16(packet, udp + 4, udpLength)
            payload.copyInto(packet, udp + 8)
        }
    }

    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
