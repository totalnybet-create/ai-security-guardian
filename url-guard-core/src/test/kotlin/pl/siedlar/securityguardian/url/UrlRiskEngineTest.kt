package pl.siedlar.securityguardian.url

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class UrlRiskEngineTest {
    private val engine = UrlRiskEngine(
        protectedBrands = listOf(
            ProtectedBrand(
                id = "ExampleBank",
                tokens = setOf("examplebank"),
                officialDomains = setOf("examplebank.com"),
            ),
        ),
    )

    @Test
    fun officialHttpsDomainRemainsSafe() {
        val result = engine.assess("https://login.examplebank.com/account")
        assertEquals(UrlRiskLevel.SAFE, result.riskLevel)
        assertEquals(0, result.riskScore)
        assertTrue(result.shouldOpenDirectly)
    }

    @Test
    fun brandTokenOutsideOfficialDomainIsHighRisk() {
        val result = engine.assess("https://examplebank-login.example/verify")
        assertTrue(result.riskScore >= 45)
        assertTrue(result.evidence.any { it.id == "brand_token_outside_official" })
        assertFalse(result.shouldOpenDirectly)
    }

    @Test
    fun brandImpersonationPlusUserInfoBecomesHighOrCritical() {
        val result = engine.assess("https://examplebank@xn--examplebank-9za.example/login")
        assertTrue(result.riskScore >= 60)
        assertTrue(result.evidence.any { it.id == "userinfo" })
        assertTrue(result.evidence.any { it.id == "correlated_impersonation" })
        assertFalse(result.shouldOpenDirectly)
    }

    @Test
    fun externalRedirectIsEvidenceButNotAutomaticallyMalware() {
        val result = engine.assess(
            "https://safe.example/redirect?url=https%3A%2F%2Fother.example%2Flogin",
        )
        assertTrue(result.evidence.any { it.id == "external_redirect" })
        assertTrue(result.riskLevel == UrlRiskLevel.LOW || result.riskLevel == UrlRiskLevel.MEDIUM)
        assertFalse(result.riskLevel == UrlRiskLevel.HIGH || result.riskLevel == UrlRiskLevel.CRITICAL)
    }

    @Test
    fun dangerousScriptSchemeIsNeverDirectOpen() {
        val result = engine.assess("javascript:alert(1)")
        assertTrue(result.riskLevel == UrlRiskLevel.HIGH || result.riskLevel == UrlRiskLevel.CRITICAL)
        assertTrue(result.evidence.any { it.id == "dangerous_scheme" })
        assertFalse(result.shouldOpenDirectly)
    }

    @Test
    fun punycodeAloneDoesNotBecomeHighRisk() {
        val result = engine.assess("https://xn--bcher-kva.example/catalog")
        assertEquals(UrlRiskLevel.LOW, result.riskLevel)
        assertTrue(result.evidence.any { it.id == "punycode" })
    }

    @Test
    fun oneEditBrandLookalikeIsDetected() {
        val result = engine.assess("https://examplebanl.com/login")
        assertTrue(result.evidence.any { it.id == "brand_near_match" })
        assertFalse(result.shouldOpenDirectly)
    }
}
