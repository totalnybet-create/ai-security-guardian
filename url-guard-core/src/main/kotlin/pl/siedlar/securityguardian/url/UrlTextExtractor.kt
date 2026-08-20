package pl.siedlar.securityguardian.url

class UrlTextExtractor(
    private val maxInputChars: Int = 16_384,
    private val maxUrlChars: Int = 8_192,
) {
    init {
        require(maxInputChars in 256..131_072)
        require(maxUrlChars in 128..maxInputChars)
    }

    fun firstCandidate(text: String): String? {
        val bounded = text.trim().take(maxInputChars)
        if (bounded.isBlank()) return null

        val direct = bounded.take(maxUrlChars)
        if (SCHEME_PREFIXES.any { prefix -> direct.startsWith(prefix, ignoreCase = true) }) {
            return trimTrailingPunctuation(direct)
        }

        val lower = bounded.lowercase()
        val start = WEB_PREFIXES
            .map { prefix -> lower.indexOf(prefix) }
            .filter { it >= 0 }
            .minOrNull()
            ?: return null

        var end = start
        while (end < bounded.length && end - start < maxUrlChars) {
            val c = bounded[end]
            if (c.isWhitespace() || c == '<' || c == '>' || c == '"' || c == '\'') break
            end++
        }
        if (end <= start) return null
        return trimTrailingPunctuation(bounded.substring(start, end))
            .takeIf(String::isNotBlank)
    }

    private fun trimTrailingPunctuation(value: String): String {
        var end = value.length
        while (end > 0 && value[end - 1] in TRAILING_PUNCTUATION) end--
        return value.substring(0, end)
    }

    private companion object {
        val WEB_PREFIXES = listOf("https://", "http://")
        val SCHEME_PREFIXES = listOf(
            "https://",
            "http://",
            "javascript:",
            "data:",
            "file:",
            "intent:",
        )
        val TRAILING_PUNCTUATION = setOf('.', ',', ';', ':', '!', '?', ')', ']', '}')
    }
}
