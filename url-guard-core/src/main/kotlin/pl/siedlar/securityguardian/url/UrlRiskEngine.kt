package pl.siedlar.securityguardian.url

import java.net.IDN
import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.util.Locale

enum class UrlRiskLevel {
    SAFE,
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL,
}

data class ProtectedBrand(
    val id: String,
    val tokens: Set<String>,
    val officialDomains: Set<String>,
) {
    init {
        require(id.isNotBlank())
        require(tokens.isNotEmpty())
        require(officialDomains.isNotEmpty())
    }
}

data class UrlEvidence(
    val id: String,
    val detail: String,
    val weight: Int,
)

data class UrlAssessment(
    val input: String,
    val normalizedHost: String?,
    val scheme: String?,
    val riskScore: Int,
    val riskLevel: UrlRiskLevel,
    val confidence: Int,
    val evidence: List<UrlEvidence>,
    val shouldOpenDirectly: Boolean,
)

class UrlRiskEngine(
    protectedBrands: List<ProtectedBrand> = emptyList(),
) {
    private val brands = protectedBrands.map(::normalizeBrand)

    fun assess(rawInput: String): UrlAssessment {
        val trimmedInput = rawInput.trim()
        val input = trimmedInput.take(MAX_INPUT_CHARS)
        if (input.isBlank()) return malformed(rawInput, "empty_url")

        val uri = runCatching { URI(input) }.getOrNull()
            ?: return malformed(rawInput, "uri_parse_failed")
        val scheme = uri.scheme?.lowercase(Locale.ROOT)
        val evidence = mutableListOf<UrlEvidence>()

        if (scheme == null) {
            evidence += UrlEvidence("missing_scheme", "Link has no explicit scheme.", 30)
        } else if (scheme in DANGEROUS_SCHEMES) {
            evidence += UrlEvidence("dangerous_scheme", "Scheme '$scheme' can invoke local/script/file behavior.", 80)
        } else if (scheme !in WEB_SCHEMES) {
            evidence += UrlEvidence("non_web_scheme", "Scheme '$scheme' is not a normal HTTP(S) web link.", 25)
        }

        val host = extractHost(uri)?.let(::normalizeHost)
        if (scheme in WEB_SCHEMES && host == null) {
            evidence += UrlEvidence("missing_host", "HTTP(S) URL has no valid canonical host.", 60)
        }

        if (!uri.rawUserInfo.isNullOrBlank()) {
            evidence += UrlEvidence("userinfo", "URL contains user-info before the host, which can visually hide the real destination.", 25)
        }

        if (scheme == "http") {
            evidence += UrlEvidence("plaintext_http", "Connection is not HTTPS.", 5)
        }

        if (host != null) {
            if (isIpLiteral(host)) {
                evidence += UrlEvidence("ip_literal", "Destination uses a literal IP address instead of a domain name.", 12)
            }
            if (host.split('.').any { it.startsWith("xn--") }) {
                evidence += UrlEvidence("punycode", "Destination contains an IDN/punycode label.", 10)
            }
            if (host.length > 100 || host.count { it == '.' } >= 5) {
                evidence += UrlEvidence("complex_host", "Destination host is unusually long or deeply nested.", 8)
            }

            val port = uri.port
            if (port != -1 && !isDefaultPort(scheme, port)) {
                evidence += UrlEvidence("nonstandard_port", "URL uses non-default port $port.", 8)
            }

            evidence += brandEvidence(host)
            evidence += nestedRedirectEvidence(uri, host)
        }

        if (trimmedInput.length > MAX_INPUT_CHARS) {
            evidence += UrlEvidence("input_truncated", "Only the bounded URL prefix was analyzed.", 10)
        }

        val brandImpersonation = evidence.any { it.id == "brand_token_outside_official" || it.id == "brand_near_match" }
        val concealment = evidence.any { it.id == "userinfo" || it.id == "punycode" || it.id == "external_redirect" }
        if (brandImpersonation && concealment) {
            evidence += UrlEvidence(
                "correlated_impersonation",
                "Brand impersonation is combined with destination-concealment signals.",
                20,
            )
        }

        val score = evidence.sumOf(UrlEvidence::weight).coerceIn(0, 100)
        val level = levelFor(score)
        val confidence = if (evidence.isEmpty()) {
            65
        } else {
            (50 + evidence.size * 7 + (evidence.maxOfOrNull(UrlEvidence::weight) ?: 0) / 3).coerceIn(0, 100)
        }

        return UrlAssessment(
            input = rawInput,
            normalizedHost = host,
            scheme = scheme,
            riskScore = score,
            riskLevel = level,
            confidence = confidence,
            evidence = evidence.sortedByDescending(UrlEvidence::weight),
            shouldOpenDirectly = scheme in WEB_SCHEMES && host != null && level <= UrlRiskLevel.LOW,
        )
    }

    private fun brandEvidence(host: String): List<UrlEvidence> {
        val results = mutableListOf<UrlEvidence>()
        val labels = host.split('.')
        brands.forEach { brand ->
            if (brand.officialDomains.any { official -> host == official || host.endsWith(".$official") }) {
                return@forEach
            }

            val tokenHit = brand.tokens.firstOrNull { token -> labels.any { label -> label.contains(token) } }
            if (tokenHit != null) {
                results += UrlEvidence(
                    "brand_token_outside_official",
                    "Host contains protected brand token '${brand.id}' outside its official domain set.",
                    45,
                )
                return@forEach
            }

            val near = brand.tokens.firstOrNull { token ->
                token.length >= 5 && labels.any { label ->
                    label.length in (token.length - 1)..(token.length + 1) && editDistanceAtMostOne(label, token)
                }
            }
            if (near != null) {
                results += UrlEvidence(
                    "brand_near_match",
                    "Host is one edit away from protected brand '${brand.id}' outside its official domains.",
                    50,
                )
            }
        }
        return results
    }

    private fun nestedRedirectEvidence(uri: URI, outerHost: String): List<UrlEvidence> {
        val rawQuery = uri.rawQuery?.take(MAX_QUERY_CHARS) ?: return emptyList()
        return rawQuery.split('&')
            .take(MAX_QUERY_PARAMS)
            .mapNotNull { parameter ->
                val separator = parameter.indexOf('=')
                if (separator <= 0) return@mapNotNull null
                val key = parameter.substring(0, separator).lowercase(Locale.ROOT)
                if (key !in REDIRECT_KEYS) return@mapNotNull null
                val value = decodeBounded(parameter.substring(separator + 1)) ?: return@mapNotNull null
                val nested = runCatching { URI(value) }.getOrNull() ?: return@mapNotNull null
                if (nested.scheme?.lowercase(Locale.ROOT) !in WEB_SCHEMES) return@mapNotNull null
                val nestedHost = extractHost(nested)?.let(::normalizeHost) ?: return@mapNotNull null
                if (nestedHost == outerHost) return@mapNotNull null
                UrlEvidence(
                    "external_redirect",
                    "URL contains an embedded redirect to a different host: $nestedHost.",
                    18,
                )
            }
            .distinctBy(UrlEvidence::detail)
            .take(2)
    }

    private fun malformed(input: String, id: String): UrlAssessment = UrlAssessment(
        input = input,
        normalizedHost = null,
        scheme = null,
        riskScore = 60,
        riskLevel = UrlRiskLevel.HIGH,
        confidence = 80,
        evidence = listOf(UrlEvidence(id, "URL cannot be safely parsed as a normal destination.", 60)),
        shouldOpenDirectly = false,
    )

    private fun normalizeBrand(brand: ProtectedBrand): ProtectedBrand = ProtectedBrand(
        id = brand.id,
        tokens = brand.tokens.map { it.lowercase(Locale.ROOT).filter(Char::isLetterOrDigit) }
            .filter(String::isNotBlank)
            .toSet(),
        officialDomains = brand.officialDomains.mapNotNull(::normalizeHost).toSet(),
    )

    private fun normalizeHost(value: String): String? = runCatching {
        val trimmed = value.trim().trim('[', ']').trimEnd('.')
        if (trimmed.contains(':') && trimmed.none { it == '.' }) {
            return@runCatching trimmed.lowercase(Locale.ROOT)
        }
        IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES)
            .lowercase(Locale.ROOT)
            .takeIf { host ->
                host.isNotBlank() &&
                    host.length <= 253 &&
                    host.split('.').all { label -> label.isNotBlank() && label.length <= 63 }
            }
    }.getOrNull()

    private fun extractHost(uri: URI): String? {
        uri.host?.let { return it }
        val authority = uri.rawAuthority ?: return null
        val withoutUser = authority.substringAfterLast('@')
        if (withoutUser.startsWith('[')) {
            return withoutUser.substringAfter('[').substringBefore(']')
        }
        return withoutUser.substringBefore(':')
    }

    private fun isIpLiteral(host: String): Boolean {
        if (host.contains(':')) return true
        val parts = host.split('.')
        return parts.size == 4 && parts.all { part ->
            part.length in 1..3 && part.all(Char::isDigit) && part.toIntOrNull() in 0..255
        }
    }

    private fun isDefaultPort(scheme: String?, port: Int): Boolean =
        (scheme == "https" && port == 443) || (scheme == "http" && port == 80)

    private fun decodeBounded(value: String): String? = runCatching {
        URLDecoder.decode(value.take(MAX_REDIRECT_VALUE_CHARS), StandardCharsets.UTF_8)
            .take(MAX_REDIRECT_VALUE_CHARS)
    }.getOrNull()

    private fun editDistanceAtMostOne(a: String, b: String): Boolean {
        if (kotlin.math.abs(a.length - b.length) > 1) return false
        var i = 0
        var j = 0
        var edits = 0
        while (i < a.length && j < b.length) {
            if (a[i] == b[j]) {
                i++
                j++
                continue
            }
            edits++
            if (edits > 1) return false
            when {
                a.length > b.length -> i++
                b.length > a.length -> j++
                else -> {
                    i++
                    j++
                }
            }
        }
        if (i < a.length || j < b.length) edits++
        return edits <= 1
    }

    private fun levelFor(score: Int): UrlRiskLevel = when (score) {
        in 0..9 -> UrlRiskLevel.SAFE
        in 10..29 -> UrlRiskLevel.LOW
        in 30..59 -> UrlRiskLevel.MEDIUM
        in 60..84 -> UrlRiskLevel.HIGH
        else -> UrlRiskLevel.CRITICAL
    }

    private companion object {
        const val MAX_INPUT_CHARS = 8_192
        const val MAX_QUERY_CHARS = 4_096
        const val MAX_QUERY_PARAMS = 64
        const val MAX_REDIRECT_VALUE_CHARS = 2_048
        val WEB_SCHEMES = setOf("http", "https")
        val DANGEROUS_SCHEMES = setOf("javascript", "data", "file", "intent")
        val REDIRECT_KEYS = setOf("url", "target", "redirect", "redirect_uri", "continue", "dest", "destination")
    }
}
