package pl.siedlar.securityguardian.voice

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class VoiceCoreTest {
    @Test
    fun `unverified reply states verification failure`() {
        val reply = SpokenReplyComposer.compose(
            explanation = "Sprawdziłem link lokalnie.",
            result = "HIGH 72/100",
            verification = "Brak pełnej reputacji zewnętrznej.",
            verified = false,
        )
        assertTrue(reply.text.contains("nie ma pozytywnej weryfikacji", ignoreCase = true))
        assertEquals(false, reply.verified)
    }

    @Test
    fun `verified reply stays bounded`() {
        val reply = SpokenReplyComposer.compose(
            explanation = "A".repeat(3_000),
            result = null,
            verification = null,
            verified = true,
        )
        assertTrue(reply.text.length <= SpokenReply.MAX_SPOKEN_CHARS)
        assertEquals(true, reply.verified)
    }

    @Test
    fun `transcript confidence is bounded`() {
        assertFailsWith<IllegalArgumentException> {
            VoiceTranscript("test", isFinal = true, confidence = 1.5f)
        }
    }
}
