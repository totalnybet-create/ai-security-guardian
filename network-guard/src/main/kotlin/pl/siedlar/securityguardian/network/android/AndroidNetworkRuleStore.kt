package pl.siedlar.securityguardian.network.android

import android.content.Context
import pl.siedlar.securityguardian.network.NetworkAction
import pl.siedlar.securityguardian.network.NetworkRule
import java.net.IDN
import java.util.Locale

class AndroidNetworkRuleStore(
    context: Context,
) {
    private val preferences = context.applicationContext.getSharedPreferences(
        "network-guard-rules-v1",
        Context.MODE_PRIVATE,
    )

    fun list(): List<NetworkRule> = preferences
        .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
        .orEmpty()
        .map { domain ->
            NetworkRule(
                id = "block-domain:$domain",
                action = NetworkAction.BLOCK,
                domainSuffix = domain,
                priority = 100,
            )
        }
        .sortedBy(NetworkRule::domainSuffix)

    fun addBlockedDomain(domain: String): NetworkRule {
        val normalized = normalizeDomain(domain)
            ?: throw IllegalArgumentException("Nieprawidłowa domena")
        val next = preferences
            .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
            .orEmpty()
            .toMutableSet()
            .apply { add(normalized) }
        check(preferences.edit().putStringSet(KEY_BLOCKED_DOMAINS, next).commit()) {
            "Nie udało się zapisać reguły sieciowej"
        }
        return NetworkRule(
            id = "block-domain:$normalized",
            action = NetworkAction.BLOCK,
            domainSuffix = normalized,
            priority = 100,
        )
    }

    fun remove(ruleId: String): Boolean {
        val prefix = "block-domain:"
        if (!ruleId.startsWith(prefix)) return false
        val domain = ruleId.removePrefix(prefix)
        val next = preferences
            .getStringSet(KEY_BLOCKED_DOMAINS, emptySet())
            .orEmpty()
            .toMutableSet()
        if (!next.remove(domain)) return false
        return preferences.edit().putStringSet(KEY_BLOCKED_DOMAINS, next).commit()
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
    }
}
