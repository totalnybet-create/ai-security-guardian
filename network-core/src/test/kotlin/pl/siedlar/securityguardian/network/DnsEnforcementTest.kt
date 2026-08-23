package pl.siedlar.securityguardian.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class DnsEnforcementTest {
    private val packetParser = IpPacketParser()
    private val dnsParser = DnsMessageParser()

    @Test
    fun nxdomainCanBeInjectedAsValidIpv4UdpResponse() {
        val dnsQuery = dnsQuery("blocked.example")
        val request = ipv4Udp(dnsQuery)
        val parsedRequest = packetParser.parse(request)
        val blockedDns = assertNotNull(DnsResponseFactory().nxdomain(dnsQuery))
        val response = assertNotNull(UdpIpResponseBuilder().buildResponse(request, parsedRequest, blockedDns))
        val parsedResponse = packetParser.parse(response)

        assertEquals(PacketParseStatus.PARSED, parsedResponse.status)
        assertEquals("10.7.0.2", parsedResponse.sourceIp)
        assertEquals("10.7.0.1", parsedResponse.destinationIp)
        assertEquals(53, parsedResponse.sourcePort)
        assertEquals(53000, parsedResponse.destinationPort)

        val dnsResponse = assertNotNull(
            dnsParser.parseUdpPayload(
                response,
                parsedResponse.transportPayloadOffset!!,
                parsedResponse.transportPayloadLength!!,
            ),
        )
        assertTrue(dnsResponse.isResponse)
        assertEquals(3, dnsResponse.responseCode)
        assertEquals("blocked.example", dnsResponse.questions.single().name)
    }

    private fun ipv4Udp(payload: ByteArray): ByteArray {
        val udpLength = 8 + payload.size
        val total = 20 + udpLength
        return ByteArray(total).also { packet ->
            packet[0] = 0x45
            put16(packet, 2, total)
            packet[8] = 64
            packet[9] = 17
            byteArrayOf(10, 7, 0, 1).copyInto(packet, 12)
            byteArrayOf(10, 7, 0, 2).copyInto(packet, 16)
            put16(packet, 20, 53000)
            put16(packet, 22, 53)
            put16(packet, 24, udpLength)
            payload.copyInto(packet, 28)
        }
    }

    private fun dnsQuery(name: String): ByteArray {
        val encoded = ArrayList<Byte>()
        name.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            encoded += bytes.size.toByte()
            bytes.forEach(encoded::add)
        }
        encoded += 0

        val query = ByteArray(12 + encoded.size + 4)
        query[0] = 0x12
        query[1] = 0x34
        query[2] = 0x01
        query[5] = 0x01
        encoded.toByteArray().copyInto(query, 12)
        val cursor = 12 + encoded.size
        put16(query, cursor, 1)
        put16(query, cursor + 2, 1)
        return query
    }

    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }
}
