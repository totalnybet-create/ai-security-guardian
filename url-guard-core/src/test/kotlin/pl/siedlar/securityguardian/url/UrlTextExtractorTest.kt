package pl.siedlar.securityguardian.url

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class UrlTextExtractorTest {
    private val extractor = UrlTextExtractor()

    @Test
    fun extractsFirstWebUrlFromSentence() {
        assertEquals(
            "https://example.com/login?a=1",
            extractor.firstCandidate("Sprawdź: https://example.com/login?a=1, dzięki"),
        )
    }

    @Test
    fun preservesDangerousDirectSchemeForRiskEngine() {
        assertEquals("javascript:alert(1", extractor.firstCandidate("javascript:alert(1)"))
    }

    @Test
    fun noUrlReturnsNull() {
        assertNull(extractor.firstCandidate("zwykły tekst bez linku"))
    }
}
