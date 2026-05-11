package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.VexAssertion;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConstraintType;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class VexAssertionMatchServiceTest {

    @Mock
    private VexAssertionRepository vexAssertionRepository;

    @Test
    void resolveReturnsExactAffectedAssertionForMatchingComponentVersion() {
        VexAssertionMatchService service = createService();
        InventoryComponent component = component("1.2.3");
        Vulnerability vulnerability = vulnerability("CVE-2026-1111");
        VulnerabilityTarget target = target(vulnerability, "vex-microsoft");
        UUID assertionId = UUID.randomUUID();

        VexAssertion assertion = assertion(assertionId, vulnerability, target, "vex-microsoft", "AFFECTED", Instant.now());
        when(vexAssertionRepository.findByTarget_IdIn(anyCollection())).thenReturn(List.of(assertion));

        ImpactEvaluationService.VexOverlayOutcome outcome = service.resolve(
                component,
                vulnerability.getId(),
                null,
                List.of(candidate(target)),
                null
        );

        assertEquals("AFFECTED", outcome.status());
        assertEquals("microsoft", outcome.provider());
        assertEquals(assertionId, outcome.assertionId());
        assertEquals(target.getId(), outcome.targetId());
    }

    @Test
    void resolveTreatsStaleNotAffectedAssertionAsUnknown() {
        VexAssertionMatchService service = createService();
        InventoryComponent component = component("1.2.3");
        Vulnerability vulnerability = vulnerability("CVE-2026-2222");
        VulnerabilityTarget target = target(vulnerability, "vex-redhat");

        VexAssertion assertion = assertion(
                UUID.randomUUID(),
                vulnerability,
                target,
                "vex-redhat",
                "NOT_AFFECTED",
                Instant.now().minusSeconds(60L * 60L * 24L * 45L)
        );
        when(vexAssertionRepository.findByTarget_IdIn(anyCollection())).thenReturn(List.of(assertion));

        RiskPolicy policy = new RiskPolicy();

        ImpactEvaluationService.VexOverlayOutcome outcome = service.resolve(
                component,
                vulnerability.getId(),
                null,
                List.of(candidate(target)),
                policy
        );

        assertEquals("UNKNOWN", outcome.status());
        assertEquals("vex_not_affected_stale_or_untrusted", outcome.reason());
        assertEquals("STALE", outcome.freshness());
        assertEquals(assertion.getId(), outcome.assertionId());
    }

    private VexAssertionMatchService createService() {
        VexPolicyService vexPolicyService = new VexPolicyService();
        ApplicabilityDecisionService applicabilityDecisionService =
                new ApplicabilityDecisionService(new ObjectMapper(), vexPolicyService);
        return new VexAssertionMatchService(
                vexAssertionRepository,
                applicabilityDecisionService,
                vexPolicyService,
                new ImpactEvaluationService(),
                new PrecedenceResolverService()
        );
    }

    private InventoryComponent component(String version) {
        InventoryComponent component = new InventoryComponent();
        ReflectionTestUtils.setField(component, "id", UUID.randomUUID());
        component.setVersion(version);
        component.setPackageName("demo");
        component.setEcosystem("maven");
        component.setPurl("pkg:maven/acme/demo@" + version);
        return component;
    }

    private Vulnerability vulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        ReflectionTestUtils.setField(vulnerability, "id", UUID.randomUUID());
        vulnerability.setExternalId(externalId);
        return vulnerability;
    }

    private VulnerabilityTarget target(Vulnerability vulnerability, String source) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        ReflectionTestUtils.setField(target, "id", UUID.randomUUID());
        target.setVulnerability(vulnerability);
        target.setSource(source);
        target.setVersionScheme(VersionScheme.SEMVER);
        target.setConstraintType(VulnerabilityConstraintType.RANGE);
        target.setVersionStart("1.0.0");
        target.setStartInclusive(true);
        target.setVersionEnd("2.0.0");
        target.setEndInclusive(false);
        return target;
    }

    private VexAssertion assertion(
            UUID assertionId,
            Vulnerability vulnerability,
            VulnerabilityTarget target,
            String sourceSystem,
            String status,
            Instant publishedAt
    ) {
        VexAssertion assertion = new VexAssertion();
        ReflectionTestUtils.setField(assertion, "id", assertionId);
        assertion.setVulnerability(vulnerability);
        assertion.setTarget(target);
        assertion.setSourceSystem(sourceSystem);
        assertion.setProvider(sourceSystem.contains("microsoft") ? "microsoft" : "redhat");
        assertion.setDocumentId("doc-1");
        assertion.setStatementKey("stmt-1");
        assertion.setStatus(status);
        assertion.setTrustTier("HIGH");
        assertion.setFreshness("UNKNOWN");
        assertion.setNormalizedProductKey("pkg:maven/acme/demo@1.2.3");
        assertion.setPublishedAt(publishedAt);
        assertion.setLastSeenAt(publishedAt);
        assertion.touch();
        return assertion;
    }

    private CorrelationCandidateService.CandidateMatch candidate(VulnerabilityTarget target) {
        return new CorrelationCandidateService.CandidateMatch(
                target,
                "purl-indexed-exact+version",
                10,
                0.91,
                Map.of("base", 0.91)
        );
    }
}
