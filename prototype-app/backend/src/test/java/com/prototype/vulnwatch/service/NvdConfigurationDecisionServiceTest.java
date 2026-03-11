package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.VulnerabilityConfigExpr;
import java.util.List;
import org.junit.jupiter.api.Test;

class NvdConfigurationDecisionServiceTest {

    private final NvdConfigurationDecisionService service = new NvdConfigurationDecisionService(new ObjectMapper());

    @Test
    void evaluatesSimpleMatchAsAffected() {
        InventoryComponent component = component("log4j", "2.14.1");
        VulnerabilityConfigExpr expr = rootExpr(0, """
                {
                  "operator": "OR",
                  "negate": false,
                  "cpeMatch": [
                    {
                      "vulnerable": true,
                      "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                    }
                  ]
                }
                """);

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, List.of(expr));
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.TRUE, decision.result());
    }

    @Test
    void evaluatesNegatedMatchAsNotAffected() {
        InventoryComponent component = component("log4j", "2.14.1");
        VulnerabilityConfigExpr expr = rootExpr(0, """
                {
                  "operator": "OR",
                  "negate": true,
                  "cpeMatch": [
                    {
                      "vulnerable": true,
                      "criteria": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                    }
                  ]
                }
                """);

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, List.of(expr));
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.FALSE, decision.result());
    }

    @Test
    void evaluatesAmbiguousIdentityAsUnknownInsteadOfNotAffected() {
        InventoryComponent component = component("spring-core", "5.3.10");
        VulnerabilityConfigExpr expr = rootExpr(0, """
                {
                  "operator": "OR",
                  "negate": false,
                  "cpeMatch": [
                    {
                      "vulnerable": true,
                      "criteria": "cpe:2.3:a:vmware:spring_framework:5.3.10:*:*:*:*:*:*:*"
                    }
                  ]
                }
                """);

        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, List.of(expr));
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
    }

    @Test
    void nvdTreeUnavailableReturnsUnknownNotAffected() {
        // BLG-003: When NVD config data is absent we cannot determine applicability.
        // Must return UNKNOWN, not TRUE (affected), to avoid systematic false positives.
        InventoryComponent component = component("some-lib", "1.0.0");
        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, List.of());
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("nvd_tree_unavailable", decision.reason());
    }

    @Test
    void nvdTreeUnavailableReturnsUnknownWhenExpressionsNull() {
        InventoryComponent component = component("some-lib", "1.0.0");
        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, null);
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN, decision.result());
        assertEquals("nvd_tree_unavailable", decision.reason());
    }

    @Test
    void debianEpochVersionComparedCorrectly() {
        // BLG-005: Debian versions with epoch must use DPKG scheme, not generic comparator.
        // A generic comparator cannot parse "0:1.1.1f-1" and would return UNKNOWN.
        // DPKG correctly strips epoch 0 and compares "1.1.1f" < "1.1.1g" → TRUE (affected).
        InventoryComponent component = component("openssl", "0:1.1.1f-1");
        component.setPurl("pkg:deb/debian/openssl@0:1.1.1f-1");
        VulnerabilityConfigExpr expr = rootExpr(0, """
                {
                  "operator": "OR",
                  "negate": false,
                  "cpeMatch": [
                    {
                      "vulnerable": true,
                      "criteria": "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
                      "versionStartIncluding": "1.0.0",
                      "versionEndExcluding": "1.1.1g"
                    }
                  ]
                }
                """);
        ApplicabilityDecisionService.ApplicabilityDecision decision = service.evaluate(component, List.of(expr));
        assertEquals(ApplicabilityDecisionService.ApplicabilityResult.TRUE, decision.result());
    }

    private InventoryComponent component(String packageName, String version) {
        InventoryComponent component = new InventoryComponent();
        component.setPackageName(packageName);
        component.setVersion(version);
        component.setPurl("pkg:maven/apache/" + packageName + "@" + version);
        return component;
    }

    private VulnerabilityConfigExpr rootExpr(int configIndex, String json) {
        VulnerabilityConfigExpr expr = new VulnerabilityConfigExpr();
        expr.setConfigIndex(configIndex);
        expr.setNodePath("configurations[" + configIndex + "].nodes[0]");
        expr.setParentPath(null);
        expr.setExprJson(json);
        expr.setSource("nvd");
        return expr;
    }
}
