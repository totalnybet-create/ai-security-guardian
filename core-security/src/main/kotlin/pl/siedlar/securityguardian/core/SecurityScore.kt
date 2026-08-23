package pl.siedlar.securityguardian.core

enum class SecurityCategory {
    APPLICATIONS,
    PERMISSIONS_PRIVACY,
    MALWARE_FILES,
    NETWORK,
    SYSTEM_CONFIGURATION,
    DEVICE_INTEGRITY,
    THREAT_INTELLIGENCE,
}

data class CategorySecurityScore(
    val category: SecurityCategory,
    val score: Int,
    val verified: Boolean,
) {
    init {
        require(score in 0..100) { "Security category score must be between 0 and 100" }
    }
}

data class SecurityScoreSummary(
    val categories: List<CategorySecurityScore>,
) {
    val verifiedCategories: List<CategorySecurityScore>
        get() = categories.filter { it.verified }

    val verifiedCategoryCount: Int
        get() = verifiedCategories.size

    val totalCategoryCount: Int
        get() = SecurityCategory.entries.size

    val coveragePercent: Int
        get() = (verifiedCategoryCount * 100) / totalCategoryCount

    val score: Int?
        get() = verifiedCategories.minOfOrNull { it.score }

    val isFullDeviceScore: Boolean
        get() = SecurityCategory.entries.all { category ->
            verifiedCategories.any { it.category == category }
        }

    companion object {
        fun p1(applications: Int, privacy: Int): SecurityScoreSummary = SecurityScoreSummary(
            categories = listOf(
                CategorySecurityScore(SecurityCategory.APPLICATIONS, applications, verified = true),
                CategorySecurityScore(SecurityCategory.PERMISSIONS_PRIVACY, privacy, verified = true),
            ),
        )
    }
}
