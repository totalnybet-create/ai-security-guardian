package pl.siedlar.securityguardian.network.android

import android.content.Context
import pl.siedlar.securityguardian.network.NetworkAction
import pl.siedlar.securityguardian.network.NetworkRule
import pl.siedlar.securityguardian.network.ThreatVerdict
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
    private val localIocs = AndroidDomainIocStore(appContext).load()

    /** Effective rules used by the DNS enforcement path. */
    fun list(): List<NetworkRule> = (listUserRules() + activeIocRules())
        .sortedWith(compareByDescending<NetworkRule> { it.priority }.thenBy { it.id })

    /** User-managed rules shown in the UI. IOC-derived rules are intentionally not removable here. */
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
            priority = USER_BLOCK_PRIORITY,
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

    private fun activeIocRules(nowEpochMs: Long = System.currentTimeMillis()): List<NetworkRule> = localIocs
        .asSequence()
        .filter { ioc -> ioc.expiresAtEpochMs == null || ioc.expiresAtEpochMs > nowEpochMs }
        .mapNotNull { ioc ->
            val action = when {
                ioc.verdict == ThreatVerdict.MALICIOUS && ioc.confidence >= MALICIOUS_BLOCK_THRESHOLD -> NetworkAction.BLOCK
                ioc.verdict == ThreatVerdict.SUSPICIOUS && ioc.confidence >= SUSPICIOUS_ASK_THRESHOLD -> NetworkAction.ASK
                else -> return@mapNotNull null
            }
            NetworkRule(
                id = "ioc:${ioc.id}",
                action = action,
                domainSuffix = ioc.domain,
                priority = if (action == NetworkAction.BLOCK) IOC_BLOCK_PRIORITY else IOC_ASK_PRIORITY,
                expiresAtEpochMs = ioc.expiresAtEpochMs,
            )
        }
        .toList()

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
        const val USER_BLOCK_PRIORITY = 100
        const val IOC_BLOCK_PRIORITY = 900
        const val IOC_ASK_PRIORITY = 800
        const val MALICIOUS_BLOCK_THRESHOLD = 80
        const val SUSPICIOUS_ASK_THRESHOLD = 60
    }
}
