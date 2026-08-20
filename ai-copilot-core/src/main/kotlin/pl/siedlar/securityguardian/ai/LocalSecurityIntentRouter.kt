package pl.siedlar.securityguardian.ai

import pl.siedlar.securityguardian.command.SecurityAction
import java.net.IDN
import java.net.URI
import java.util.Locale

class LocalSecurityIntentRouter {
    fun route(
        text: String,
        allowedActions: Set<SecurityAction>,
    ): ProposedSecurityAction? {
        val raw = text.trim()
        if (raw.isBlank() || raw.length > MAX_INPUT_CHARS) return null
        val lower = raw.lowercase(Locale("pl", "PL"))

        fun proposed(action: SecurityAction, arguments: Map<String, String> = emptyMap()): ProposedSecurityAction? =
            action.takeIf(allowedActions::contains)?.let { ProposedSecurityAction(it, arguments) }

        if (containsAny(lower, "pełny skan", "pelny skan", "zeskanuj telefon", "skanuj cały telefon", "skanuj caly telefon")) {
            return proposed(SecurityAction.RUN_FULL_SCAN)
        }

        if (containsAny(lower, "sprawdź prywatność", "sprawdz prywatnosc", "czy ktoś mnie podsłuchuje", "czy ktos mnie podsluchuje", "sprawdź mikrofon", "sprawdz mikrofon", "sprawdź kamerę", "sprawdz kamere")) {
            return proposed(SecurityAction.CHECK_PRIVACY)
        }

        extractUrl(raw)?.let { url ->
            if (containsAny(lower, "sprawdź link", "sprawdz link", "sprawdź url", "sprawdz url", "czy ten link")) {
                return proposed(SecurityAction.CHECK_URL, mapOf("url" to url))
            }
        }

        if (containsAny(lower, "zablokuj domenę", "zablokuj domene", "blokuj domenę", "blokuj domene")) {
            extractDomain(raw)?.let { domain ->
                return proposed(SecurityAction.BLOCK_DOMAIN, mapOf("domain" to domain))
            }
        }

        if (containsAny(lower, "zezwól domenie", "zezwol domenie", "pozwól domenie", "pozwol domenie", "tymczasowo zezwól", "tymczasowo zezwol")) {
            extractDomain(raw)?.let { domain ->
                return proposed(
                    SecurityAction.ALLOW_DOMAIN_TEMPORARILY,
                    mapOf("domain" to domain, "durationMinutes" to DEFAULT_TEMP_ALLOW_MINUTES.toString()),
                )
            }
        }

        if (containsAny(lower, "sprawdź aplikację", "sprawdz aplikacje", "sprawdź apkę", "sprawdz apke")) {
            PACKAGE_REGEX.find(raw)?.value?.let { packageName ->
                return proposed(SecurityAction.CHECK_APP, mapOf("packageName" to packageName))
            }
        }

        return null
    }

    private fun extractUrl(text: String): String? = URL_REGEX.find(text)
        ?.value
        ?.trimEnd('.', ',', ';', ':', '!', '?', ')', ']', '}')
        ?.take(MAX_URL_CHARS)
        ?.takeIf { candidate ->
            runCatching {
                val uri = URI(candidate)
                uri.scheme?.lowercase(Locale.ROOT) in setOf("http", "https") && !uri.host.isNullOrBlank()
            }.getOrDefault(false)
        }

    private fun extractDomain(text: String): String? {
        val candidates = DOMAIN_REGEX.findAll(text).map { it.value }.toList().asReversed()
        return candidates.firstNotNullOfOrNull { candidate ->
            normalizeDomain(candidate.removePrefix("www."))
        }
    }

    private fun normalizeDomain(value: String): String? = runCatching {
        IDN.toASCII(value.trim().trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
            .lowercase(Locale.ROOT)
            .takeIf { domain ->
                domain.isNotBlank() &&
                    domain.length <= 253 &&
                    domain.contains('.') &&
                    domain.split('.').all { label -> label.isNotBlank() && label.length <= 63 }
            }
    }.getOrNull()

    private fun containsAny(value: String, vararg needles: String): Boolean = needles.any(value::contains)

    private companion object {
        const val MAX_INPUT_CHARS = 8_192
        const val MAX_URL_CHARS = 4_096
        const val DEFAULT_TEMP_ALLOW_MINUTES = 10
        val URL_REGEX = Regex("https?://[^\\s<>\\\"']+", RegexOption.IGNORE_CASE)
        val DOMAIN_REGEX = Regex("(?i)\\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}\\b")
        val PACKAGE_REGEX = Regex("\\b[a-zA-Z0-9_]+(?:\\.[a-zA-Z0-9_]+){1,}\\b")
    }
}
