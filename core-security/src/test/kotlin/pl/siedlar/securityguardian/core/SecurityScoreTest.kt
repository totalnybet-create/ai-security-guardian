package pl.siedlar.securityguardian.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class SecurityScoreTest {
    @Test
    fun p1ScoreUsesWeakestVerifiedCategoryAndShowsPartialCoverage() {
        val summary = SecurityScoreSummary.p1(
            applications = 92,
            privacy = 61,
        )

        assertEquals(61, summary.score)
        assertEquals(2, summary.verifiedCategoryCount)
        assertEquals(7, summary.totalCategoryCount)
        assertEquals(28, summary.coveragePercent)
        assertFalse(summary.isFullDeviceScore)
    }

    @Test
    fun fullCoverageIsReportedOnlyWhenEveryCategoryIsVerified() {
        val summary = SecurityScoreSummary(
            SecurityCategory.entries.map { category ->
                CategorySecurityScore(category, 90, verified = true)
            },
        )

        assertEquals(90, summary.score)
        assertEquals(100, summary.coveragePercent)
        assertTrue(summary.isFullDeviceScore)
    }
}
