package pl.siedlar.securityguardian.network

class DnsResponseFactory(
    private val parser: DnsMessageParser = DnsMessageParser(),
) {
    fun nxdomain(query: ByteArray): ByteArray? {
        val metadata = parser.parseUdpPayload(query) ?: return null
        if (metadata.isResponse) return null
        val copyLength = metadata.wireQuestionSectionLength
        if (copyLength !in 12..query.size) return null

        val response = query.copyOf(copyLength)
        val originalFlags = u16(response, 2)
        val opcode = originalFlags and 0x7800
        val recursionDesired = originalFlags and 0x0100
        val responseFlags = 0x8000 or opcode or recursionDesired or 0x0080 or RCODE_NXDOMAIN
        put16(response, 2, responseFlags)
        put16(response, 6, 0)
        put16(response, 8, 0)
        put16(response, 10, 0)
        return response
    }

    private fun u8(value: Byte): Int = value.toInt() and 0xFF
    private fun u16(data: ByteArray, offset: Int): Int = (u8(data[offset]) shl 8) or u8(data[offset + 1])
    private fun put16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private companion object {
        const val RCODE_NXDOMAIN = 3
    }
}
