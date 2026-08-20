package pl.siedlar.securityguardian.network

import java.net.IDN
import java.util.Locale

data class DnsQuestion(
    val name: String,
    val type: Int,
    val queryClass: Int,
)

data class DnsMessageMetadata(
    val id: Int,
    val isResponse: Boolean,
    val truncated: Boolean,
    val recursionDesired: Boolean,
    val responseCode: Int,
    val questions: List<DnsQuestion>,
)

class DnsMessageParser(
    private val maxQuestions: Int = 16,
    private val maxPointerDepth: Int = 16,
) {
    init {
        require(maxQuestions in 1..64)
        require(maxPointerDepth in 1..64)
    }

    fun parseUdpPayload(payload: ByteArray, offset: Int = 0, length: Int = payload.size - offset): DnsMessageMetadata? {
        if (offset < 0 || length < 0 || offset + length > payload.size) return null
        if (length < DNS_HEADER) return null
        val end = offset + length

        val id = u16(payload, offset)
        val flags = u16(payload, offset + 2)
        val questionCount = u16(payload, offset + 4)
        if (questionCount > maxQuestions) return null

        var cursor = offset + DNS_HEADER
        val questions = ArrayList<DnsQuestion>(questionCount)
        repeat(questionCount) {
            val decoded = decodeName(payload, cursor, offset, end) ?: return null
            cursor = decoded.nextOffset
            if (cursor + 4 > end) return null
            val type = u16(payload, cursor)
            val queryClass = u16(payload, cursor + 2)
            cursor += 4
            questions += DnsQuestion(
                name = decoded.name,
                type = type,
                queryClass = queryClass,
            )
        }

        return DnsMessageMetadata(
            id = id,
            isResponse = flags and 0x8000 != 0,
            truncated = flags and 0x0200 != 0,
            recursionDesired = flags and 0x0100 != 0,
            responseCode = flags and 0x000F,
            questions = questions,
        )
    }

    private fun decodeName(
        data: ByteArray,
        start: Int,
        base: Int,
        end: Int,
    ): DecodedName? {
        var cursor = start
        var nextOffset = -1
        var pointerDepth = 0
        val labels = ArrayList<String>()
        val visitedPointers = hashSetOf<Int>()
        var wireLength = 1

        while (true) {
            if (cursor !in base until end) return null
            val length = u8(data[cursor])

            when {
                length == 0 -> {
                    if (nextOffset < 0) nextOffset = cursor + 1
                    break
                }

                length and 0xC0 == 0xC0 -> {
                    if (cursor + 1 >= end) return null
                    val pointer = ((length and 0x3F) shl 8) or u8(data[cursor + 1])
                    val target = base + pointer
                    if (target !in base until end) return null
                    if (!visitedPointers.add(target)) return null
                    pointerDepth++
                    if (pointerDepth > maxPointerDepth) return null
                    if (nextOffset < 0) nextOffset = cursor + 2
                    cursor = target
                }

                length and 0xC0 != 0 -> return null

                else -> {
                    if (length > 63) return null
                    val labelStart = cursor + 1
                    val labelEnd = labelStart + length
                    if (labelEnd > end) return null
                    val label = data.copyOfRange(labelStart, labelEnd).toString(Charsets.US_ASCII)
                    if (label.any { it.code !in 0x21..0x7E }) return null
                    labels += label
                    wireLength += length + 1
                    if (wireLength > 255) return null
                    cursor = labelEnd
                }
            }
        }

        val normalized = normalizeDomain(labels.joinToString(".")) ?: return null
        return DecodedName(
            name = normalized,
            nextOffset = nextOffset.takeIf { it >= 0 } ?: return null,
        )
    }

    private fun normalizeDomain(value: String): String? = runCatching {
        IDN.toASCII(value.trim().trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
            .lowercase(Locale.ROOT)
            .takeIf(String::isNotBlank)
    }.getOrNull()

    private fun u8(value: Byte): Int = value.toInt() and 0xFF
    private fun u16(data: ByteArray, offset: Int): Int = (u8(data[offset]) shl 8) or u8(data[offset + 1])

    private data class DecodedName(
        val name: String,
        val nextOffset: Int,
    )

    private companion object {
        const val DNS_HEADER = 12
    }
}
