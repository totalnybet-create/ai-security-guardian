package pl.siedlar.securityguardian.network.android

import android.content.Context
import pl.siedlar.securityguardian.network.DomainIocPolicyAdapter
import pl.siedlar.securityguardian.network.NetworkAction
import pl.siedlar.securityguardian.network.NetworkRule
import java.net.IDN
import java.util.Locale

class AndroidNetworkRuleStore(
    context: Context,
) {
    private val appContext = context.applicationContext
    private val preferences = appContext.getSharedPreferences(
        "network-guard-rules-v1",
        Context.MODE_PRIVATE,
    )
    private val iocStore = AndroidDomainIocStore(appContext)
    private val iocPolicyAdapter = DomainIocPolicyAdapter()

    /** Effective rules used by the DNS enforcement path. */
    fun list(): List<NetworkRule> {
        val now = System.currentTimeMillis()
        val temporary = listTemporaryAllowRules(now)
        val iocRules = iocPolicyAdapter.toRules(iocStore.load(), now)
        return (listUserRules() + temporary + iocRules)
            .sortedWith(compareByDescending<NetworkRule> { it.priority }.thenBy { it.id })
    }

    /** User-managed permanent BLOCK rules shown in the UI. */
    fun listUserRules(): List<NetworkRule> = preferences
        .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
        .orEmpty()
        .map { domain ->
            NetworkRule(
                id = "block-domain:$domain",
                action = NetworkAction.BLOCK,
                domainSuffix = domain,
                priority = USER_BLOCK_PRIORITY,
            )
        }
        .sortedBy(NetworkRule::domainSuffix)

    fun isUserBlockedDomain(domain: String): Boolean {
        val normalized = normalizeDomain(domain) ?: return false
        return preferences
            .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
            .orEmpty()
            .any { stored -> normalizeDomain(stored) == normalized }
    }

    fun addBlockedDomain(domain: String): NetworkRule {
        val normalized = normalizeDomain(domain)
            ?: throw IllegalArgumentException("Nieprawidłowa domena")
        val next = preferences
            .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
            .orEmpty()
            .mapNotNull(::normalizeDomain)
            .toMutableSet()
            .apply { add(normalized) }
        check(preferences.edit().putStringSet(KEY_BLOCKED_DOMAINS, next).commit()) {
            "Nie udało się zapisać reguły sieciowej"
        }
        return NetworkRule(
            id = "block-domain:$normalized",
            action = NetworkAction.BLOCK,
            domainSuffix = normalized,
            priority = USER_BLOCK_PRIORITY,
        )
    }

    fun allowDomainTemporarily(
        domain: String,
        durationMinutes: Int,
        nowEpochMs: Long = System.currentTimeMillis(),
    ): NetworkRule {
        require(durationMinutes in 1..MAX_TEMP_ALLOW_MINUTES) {
            "Tymczasowe zezwolenie musi mieć od 1 do $MAX_TEMP_ALLOW_MINUTES minut"
        }
        val normalized = normalizeDomain(domain)
            ?: throw IllegalArgumentException("Nieprawidłowa domena")
        val expiresAt = Math.addExact(nowEpochMs, durationMinutes * 60_000L)
        val encoded = encodeTemporary(normalized, expiresAt)
        val active = preferences
            .getStringSet(KEY_TEMP_ALLOWED_DOMAINS, emptySet())
            .orEmpty()
            .mapNotNull(::decodeTemporary)
            .filter { (_, expiry) -> expiry > nowEpochMs }
            .filterNot { (existingDomain, _) -> existingDomain == normalized }
            .map { (existingDomain, expiry) -> encodeTemporary(existingDomain, expiry) }
            .toMutableSet()
            .apply { add(encoded) }
        check(preferences.edit().putStringSet(KEY_TEMP_ALLOWED_DOMAINS, active).commit()) {
            "Nie udało się zapisać tymczasowego zezwolenia"
        }
        return temporaryRule(normalized, expiresAt)
    }

    fun remove(ruleId: String): Boolean {
        val prefix = "block-domain:"
        if (!ruleId.startsWith(prefix)) return false
        val domain = normalizeDomain(ruleId.removePrefix(prefix)) ?: return false
        val next = preferences
            .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
            .orEmpty()
            .mapNotNull(::normalizeDomain)
            .toMutableSet()
        if (!next.remove(domain)) return false
        return preferences.edit().putStringSet(KEY_BLOCKED_DOMAINS, next).commit()
    }

    private fun listTemporaryAllowRules(nowEpochMs: Long): List<NetworkRule> {
        val raw = preferences.getStringSet(KEY_TEMP_ALLOWED_DOMAINS, emptySet()).orEmpty()
        val active = raw
            .mapNotNull(::decodeTemporary)
            .filter { (_, expiry) -> expiry > nowEpochMs }
        val canonical = active.map { (domain, expiry) -> encodeTemporary(domain, expiry) }.toSet()
        if (canonical != raw) {
            preferences.edit().putStringSet(KEY_TEMP_ALLOWED_DOMAINS, canonical).apply()
        }
        return active.map { (domain, expiry) -> temporaryRule(domain, expiry) }
    }

    private fun temporaryRule(domain: String, expiresAt: Long): NetworkRule = NetworkRule(
        id = "temp-allow-domain:$domain:$expiresAt",
        action = NetworkAction.TEMPORARY_ALLOW,
        domainSuffix = domain,
        priority = TEMP_ALLOW_PRIORITY,
        expiresAtEpochMs = expiresAt,
    )

    private fun encodeTemporary(domain: String, expiresAt: Long): String = "$domain|$expiresAt"

    private fun decodeTemporary(value: String): Pair<String, Long>? {
        val separator = value.lastIndexOf('|')
        if (separator <= 0 || separator == value.lastIndex) return null
        val domain = normalizeDomain(value.substring(0, separator)) ?: return null
        val expiry = value.substring(separator + 1).toLongOrNull() ?: return null
        return domain to expiry
    }

    private fun normalizeDomain(value: String): String? = runCatching {
        IDN.toASCII(value.trim().trimEnd('.'), IDN.USE_STD3_ASCII_RULES)
            .lowercase(Locale.ROOT)
            .takeIf { domain ->
                domain.isNotBlank() &&
                    domain.length <= 253 &&
                    domain.split('.').all { label -> label.isNotBlank() && label.length <= 63 }
            }
    }.getOrNull()

    private companion object {
        const val KEY_BLOCKED_DOMAINS = "blocked-domains"
        const val KEY_TEMP_ALLOWED_DOMAINS = "temporary-allowed-domains"
        const val USER_BLOCK_PRIORITY = 100
        const val TEMP_ALLOW_PRIORITY = 1_000
        const val MAX_TEMP_ALLOW_MINUTES = 24 * 60
    }
}
