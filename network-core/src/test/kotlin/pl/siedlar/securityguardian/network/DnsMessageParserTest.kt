package pl.siedlar.securityguardian.network

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DnsMessageParserTest {
    private val parser = DnsMessageParser()

    @Test
    fun parsesBoundedQuestionMetadata() {
        val message = query("Example.COM")
        val result = parser.parseUdpPayload(message)

        requireNotNull(result)
        assertEquals(false, result.isResponse)
        assertEquals(1, result.questions.size)
        assertEquals("example.com", result.questions.single().name)
        assertEquals(1, result.questions.single().type)
        assertEquals(1, result.questions.single().queryClass)
    }

    @Test
    fun compressionPointerLoopIsRejected() {
        val message = ByteArray(18)
        message[2] = 0x01
        message[5] = 0x01
        message[12] = 0xC0.toByte()
        message[13] = 0x0C
        message[14] = 0x00
        message[15] = 0x01
        message[16] = 0x00
        message[17] = 0x01

        assertNull(parser.parseUdpPayload(message))
    }

    @Test
    fun tooManyQuestionsAreRejectedBeforeAllocation() {
        val message = ByteArray(12)
        message[4] = 0x00
        message[5] = 0x40
        assertNull(parser.parseUdpPayload(message))
    }

    @Test
    fun responseFlagsAreExposedWithoutParsingPayloadContent() {
        val message = query("safe.example").copyOf()
        message[2] = 0x83.toByte()
        message[3] = 0x83.toByte()

        val result = parser.parseUdpPayload(message)
        requireNotNull(result)
        assertTrue(result.isResponse)
        assertTrue(result.truncated)
        assertEquals(3, result.responseCode)
    }

    private fun query(name: String): ByteArray {
        val encoded = encodeName(name)
        val message = ByteArray(12 + encoded.size + 4)
        message[0] = 0x12
        message[1] = 0x34
        message[2] = 0x01
        message[5] = 0x01
        encoded.copyInto(message, 12)
        val cursor = 12 + encoded.size
        message[cursor] = 0x00
        message[cursor + 1] = 0x01
        message[cursor + 2] = 0x00
        message[cursor + 3] = 0x01
        return message
    }

    private fun encodeName(name: String): ByteArray {
        val output = ArrayList<Byte>()
        name.split('.').forEach { label ->
            val bytes = label.toByteArray(Charsets.US_ASCII)
            output += bytes.size.toByte()
            bytes.forEach(output::add)
        }
        output += 0
        return output.toByteArray()
    }
}
