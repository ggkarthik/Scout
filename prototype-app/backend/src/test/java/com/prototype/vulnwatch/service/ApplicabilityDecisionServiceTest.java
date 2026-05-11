package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.VulnerabilityConstraintType;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class ApplicabilityDecisionServiceTest {

    private final ApplicabilityDecisionService service =
            new ApplicabilityDecisionService(new ObjectMapper(), new VexPolicyService());

    @Test
    void returnsVersionUnknownWhenComponentVersionMissing() {
        InventoryComponent component = component(null);
        VulnerabilityTarget target = rangeTarget(VersionScheme.SEMVER, "1.0.0", true, "2.0.0", true);

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("VERSION_UNKNOWN", decision.reason());
        assertEquals("VERSION_UNKNOWN", decision.trace().get("finalReason"));
    }

    @Test
    void evaluatesExactVersionAsTrue() {
        InventoryComponent component = component("2.14.1");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVersionScheme(VersionScheme.MAVEN);
        target.setConstraintType(VulnerabilityConstraintType.EXACT);
        target.setVersionExact("2.14.1");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.TRUE, decision.result());
        assertEquals("exact_version_match", decision.reason());
        assertEquals("exact_version_match", decision.trace().get("finalReason"));
    }

    @Test
    void evaluatesRangeExclusiveBoundAsFalse() {
        InventoryComponent component = component("2.14.1");
        VulnerabilityTarget target = rangeTarget(VersionScheme.MAVEN, "2.14.1", false, "2.20.0", true);

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.FALSE, decision.result());
        assertEquals("at_or_below_start_exclusive", decision.reason());
        assertEquals("at_or_below_start_exclusive", decision.trace().get("finalReason"));
    }

    @Test
    void evaluatesIntroducedFixedWindow() {
        InventoryComponent affected = component("2.25.0");
        InventoryComponent fixed = component("2.31.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVersionScheme(VersionScheme.PEP440);
        target.setConstraintType(VulnerabilityConstraintType.INTRODUCED_FIXED);
        target.setIntroduced("2.0.0");
        target.setFixed("2.31.0");

        ApplicabilityDecisionService.ApplicabilityDecision affectedDecision = service.evaluate(affected, target);
        ApplicabilityDecisionService.ApplicabilityDecision fixedDecision = service.evaluate(fixed, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.TRUE, affectedDecision.result());
        assertEquals("within_constraints", affectedDecision.reason());
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.FALSE, fixedDecision.result());
        assertEquals("at_or_above_fixed", fixedDecision.reason());
    }

    @Test
    void returnsUnknownOnVersionParserError() {
        InventoryComponent component = component("1.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVersionScheme(VersionScheme.PEP440);
        target.setConstraintType(VulnerabilityConstraintType.EXACT);
        target.setVersionExact("not-a-valid-pep440");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("exact_compare_error", decision.reason());
        assertEquals("exact_compare_error", decision.trace().get("finalReason"));
        assertTrue(decision.trace().containsKey("checks"));
    }

    @Test
    void vexNotAffectedOverridesVersionEvaluation() {
        InventoryComponent component = component(null);
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-microsoft");
        target.setQualifiersJson("{\"vexStatus\":\"NOT_AFFECTED\",\"vexPublishedAt\":\"" + freshVexPublishedAt() + "\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.FALSE, decision.result());
        assertEquals("vex_not_affected", decision.reason());
    }

    @Test
    void vexNotAffectedStaleAssertionBecomesUnknown() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-redhat");
        target.setQualifiersJson("{\"vexStatus\":\"NOT_AFFECTED\",\"vexPublishedAt\":\""
                + Instant.now().minus(Duration.ofDays(40)) + "\"}");

        RiskPolicy policy = new RiskPolicy();

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target, policy);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("vex_not_affected_stale_or_untrusted", decision.reason());
        assertEquals("STALE", decision.trace().get("vexFreshnessOutcome"));
    }

    @Test
    void vexFixedFreshAssertionSuppressesExposure() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-microsoft");
        target.setQualifiersJson("{\"vexStatus\":\"FIXED\",\"vexPublishedAt\":\"" + freshVexPublishedAt() + "\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.FALSE, decision.result());
        assertEquals("vex_fixed", decision.reason());
    }

    @Test
    void vexUnderInvestigationReturnsUnknown() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-redhat");
        target.setQualifiersJson("{\"vexStatus\":\"UNDER_INVESTIGATION\",\"vexPublishedAt\":\"" + freshVexPublishedAt() + "\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("vex_under_investigation", decision.reason());
    }

    @Test
    void vexKnownAffectedReturnsTrue() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-redhat");
        target.setQualifiersJson("{\"vexStatus\":\"KNOWN_AFFECTED\",\"vexPublishedAt\":\"" + freshVexPublishedAt() + "\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.TRUE, decision.result());
        assertEquals("vex_known_affected", decision.reason());
    }

    @Test
    void evaluateCorrelationIgnoresVexDispositionAndUsesExactSoftwareVersionMatch() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-microsoft");
        target.setQualifiersJson("{\"vexStatus\":\"NOT_AFFECTED\",\"vexPublishedAt\":\"" + freshVexPublishedAt() + "\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluateCorrelation(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.TRUE, decision.result());
        assertEquals("within_constraints", decision.reason());
        assertEquals("correlation-only", decision.trace().get("vexEvaluationMode"));
    }

    @Test
    void vexNotAffectedUntrustedAssertionBecomesUnknown() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-unknown");
        target.setQualifiersJson("{\"vexStatus\":\"NOT_AFFECTED\",\"vexTrustTier\":\"LOW\",\"vexPublishedAt\":\"" + freshVexPublishedAt() + "\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("vex_not_affected_stale_or_untrusted", decision.reason());
    }

    @Test
    void vexNotAffectedWithoutDateIsNotTrustedForSuppressionByDefault() {
        InventoryComponent component = component("1.0.0");
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setSource("vex-microsoft");
        target.setQualifiersJson("{\"vexStatus\":\"NOT_AFFECTED\"}");

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, target);

        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("vex_not_affected_stale_or_untrusted", decision.reason());
        assertEquals("NO_DATE_TREAT_AS_STALE", decision.trace().get("vexFreshnessOutcome"));
    }

    private VulnerabilityTarget rangeTarget(
            VersionScheme scheme,
            String start,
            boolean startInclusive,
            String end,
            boolean endInclusive
    ) {
        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVersionScheme(scheme);
        target.setConstraintType(VulnerabilityConstraintType.RANGE);
        target.setVersionStart(start);
        target.setStartInclusive(startInclusive);
        target.setVersionEnd(end);
        target.setEndInclusive(endInclusive);
        return target;
    }

    private String freshVexPublishedAt() {
        return Instant.now().minus(Duration.ofDays(7)).toString();
    }

    private InventoryComponent component(String version) {
        InventoryComponent component = new InventoryComponent();
        component.setVersion(version);
        component.setPackageName("pkg");
        component.setEcosystem("maven");
        component.setPurl("pkg:maven/acme/pkg@" + (version == null ? "unknown" : version));
        return component;
    }
}
