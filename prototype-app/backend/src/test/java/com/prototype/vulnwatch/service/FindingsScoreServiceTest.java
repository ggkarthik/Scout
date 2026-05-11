package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Vulnerability;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

class FindingsScoreServiceTest {

    private FindingsScoreService service;

    @BeforeEach
    void setUp() {
        service = new FindingsScoreService(new ObjectMapper());
    }

    @Test
    void returnsZeroForEmptyConfig() {
        Finding finding = mockFinding("CRITICAL", 9.5, true, BusinessCriticality.HIGH);
        assertEquals(0.0, service.compute("[]", finding), 0.001);
        assertEquals(0.0, service.compute(null, finding), 0.001);
        assertEquals(0.0, service.compute("  ", finding), 0.001);
    }

    @Test
    void matchesSeverityIsConditionAndScalesTo10() throws Exception {
        // Config: severity == CRITICAL → weight 0.6; severity == HIGH → weight 0.3
        String config = """
                [{"table":"VULNERABILITY","column":"severity",
                  "values":[
                    {"operator":"is","value":"CRITICAL","weight":0.6},
                    {"operator":"is","value":"HIGH","weight":0.3}
                  ]}]
                """;

        Finding critical = mockFinding("CRITICAL", 9.5, false, BusinessCriticality.MEDIUM);
        assertEquals(6.0, service.compute(config, critical), 0.001);

        Finding high = mockFinding("HIGH", 7.0, false, BusinessCriticality.MEDIUM);
        assertEquals(3.0, service.compute(config, high), 0.001);

        Finding medium = mockFinding("MEDIUM", 5.0, false, BusinessCriticality.MEDIUM);
        assertEquals(0.0, service.compute(config, medium), 0.001);
    }

    @Test
    void numericGreaterThanConditionMatchesCvssScore() throws Exception {
        String config = """
                [{"table":"VULNERABILITY","column":"cvssScore",
                  "values":[{"operator":">=","value":"9.0","weight":0.5}]}]
                """;

        Finding high = mockFinding("CRITICAL", 9.5, false, BusinessCriticality.MEDIUM);
        assertEquals(5.0, service.compute(config, high), 0.001);

        Finding low = mockFinding("HIGH", 7.0, false, BusinessCriticality.MEDIUM);
        assertEquals(0.0, service.compute(config, low), 0.001);
    }

    @Test
    void rangeConditionAndsBothBounds() throws Exception {
        // > 6 AND <= 8 → weight 0.3; cvss 9.5 is > 6 but NOT <= 8 → no match
        String config = """
                [{"table":"VULNERABILITY","column":"cvssScore",
                  "values":[{"operator":">","value":"6","operator2":"<=","value2":"8","weight":0.3}]}]
                """;

        Finding inRange = mockFinding("HIGH", 7.5, false, BusinessCriticality.MEDIUM);
        assertEquals(3.0, service.compute(config, inRange), 0.001);

        Finding tooHigh = mockFinding("CRITICAL", 9.5, false, BusinessCriticality.MEDIUM);
        assertEquals(0.0, service.compute(config, tooHigh), 0.001);

        Finding tooLow = mockFinding("LOW", 5.0, false, BusinessCriticality.MEDIUM);
        assertEquals(0.0, service.compute(config, tooLow), 0.001);
    }

    @Test
    void booleanInKevCondition() throws Exception {
        String config = """
                [{"table":"VULNERABILITY","column":"isInKev",
                  "values":[{"operator":"is","value":"true","weight":0.4}]}]
                """;

        Finding inKev = mockFinding("HIGH", 7.0, true, BusinessCriticality.MEDIUM);
        assertEquals(4.0, service.compute(config, inKev), 0.001);

        Finding notInKev = mockFinding("HIGH", 7.0, false, BusinessCriticality.MEDIUM);
        assertEquals(0.0, service.compute(config, notInKev), 0.001);
    }

    @Test
    void assetBusinessCriticalityCondition() throws Exception {
        String config = """
                [{"table":"ASSET","column":"businessCriticality",
                  "values":[{"operator":"is","value":"CRITICAL","weight":0.3}]}]
                """;

        Finding criticalAsset = mockFinding("MEDIUM", 5.0, false, BusinessCriticality.CRITICAL);
        assertEquals(3.0, service.compute(config, criticalAsset), 0.001);

        Finding lowAsset = mockFinding("MEDIUM", 5.0, false, BusinessCriticality.LOW);
        assertEquals(0.0, service.compute(config, lowAsset), 0.001);
    }

    @Test
    void multipleColumnsTotalWeightsSummed() throws Exception {
        // severity CRITICAL → 0.5; business_criticality CRITICAL → 0.3 → total 0.8 → 8.0
        String config = """
                [
                  {"table":"VULNERABILITY","column":"severity",
                   "values":[{"operator":"is","value":"CRITICAL","weight":0.5}]},
                  {"table":"ASSET","column":"businessCriticality",
                   "values":[{"operator":"is","value":"CRITICAL","weight":0.3}]}
                ]
                """;

        Finding both = mockFinding("CRITICAL", 9.5, false, BusinessCriticality.CRITICAL);
        assertEquals(8.0, service.compute(config, both), 0.001);
    }

    @Test
    void perColumnMaxWeightTaken() throws Exception {
        // Same column, two values → only max matching weight counts
        String config = """
                [{"table":"VULNERABILITY","column":"severity",
                  "values":[
                    {"operator":"is","value":"CRITICAL","weight":0.6},
                    {"operator":"is","value":"HIGH","weight":0.3}
                  ]}]
                """;

        // Finding matches CRITICAL only → max = 0.6 → 6.0
        Finding critical = mockFinding("CRITICAL", 9.5, false, BusinessCriticality.MEDIUM);
        assertEquals(6.0, service.compute(config, critical), 0.001);
    }

    @Test
    void scoreIsCappedAt10() throws Exception {
        // Weights sum > 1 (bad config) → should still cap at 10
        String config = """
                [
                  {"table":"VULNERABILITY","column":"severity",
                   "values":[{"operator":"is","value":"CRITICAL","weight":0.7}]},
                  {"table":"VULNERABILITY","column":"isInKev",
                   "values":[{"operator":"is","value":"true","weight":0.8}]}
                ]
                """;

        Finding both = mockFinding("CRITICAL", 9.5, true, BusinessCriticality.MEDIUM);
        assertEquals(10.0, service.compute(config, both), 0.001);
    }

    @Test
    void invalidJsonConfigReturnsZero() {
        Finding finding = mockFinding("CRITICAL", 9.5, true, BusinessCriticality.HIGH);
        assertEquals(0.0, service.compute("{not valid json}", finding), 0.001);
    }

    // ── helpers ────────────────────────────────────────────────────────────────

    private Finding mockFinding(String severity, double cvssScore, boolean inKev,
            BusinessCriticality criticality) {
        Vulnerability vuln = Mockito.mock(Vulnerability.class);
        Mockito.when(vuln.getSeverity()).thenReturn(severity);
        Mockito.when(vuln.getCvssScore()).thenReturn(cvssScore);
        Mockito.when(vuln.isInKev()).thenReturn(inKev);
        Mockito.when(vuln.getEpssScore()).thenReturn(null);
        Mockito.when(vuln.getAttackVector()).thenReturn(null);
        Mockito.when(vuln.getAttackComplexity()).thenReturn(null);
        Mockito.when(vuln.getPrivilegesRequired()).thenReturn(null);
        Mockito.when(vuln.getUserInteraction()).thenReturn(null);
        Mockito.when(vuln.getScope()).thenReturn(null);
        Mockito.when(vuln.getVulnStatus()).thenReturn(null);

        Asset asset = Mockito.mock(Asset.class);
        Mockito.when(asset.getBusinessCriticality()).thenReturn(criticality);
        Mockito.when(asset.getType()).thenReturn(com.prototype.vulnwatch.domain.AssetType.HOST);
        Mockito.when(asset.getState()).thenReturn(com.prototype.vulnwatch.domain.AssetState.ACTIVE);
        Mockito.when(asset.getEnvironment()).thenReturn(null);
        Mockito.when(asset.getOwnerTeam()).thenReturn(null);
        Mockito.when(asset.getCloudProvider()).thenReturn(null);
        Mockito.when(asset.getCloudRegion()).thenReturn(null);

        InventoryComponent comp = Mockito.mock(InventoryComponent.class);
        Mockito.when(comp.getEcosystem()).thenReturn("maven");
        Mockito.when(comp.getPackageName()).thenReturn("log4j");
        Mockito.when(comp.getVersion()).thenReturn("2.14.1");
        Mockito.when(comp.getPurl()).thenReturn(null);
        Mockito.when(comp.getIsEol()).thenReturn(null);
        Mockito.when(comp.getEolDate()).thenReturn(null);

        Finding finding = Mockito.mock(Finding.class);
        Mockito.when(finding.getVulnerability()).thenReturn(vuln);
        Mockito.when(finding.getAsset()).thenReturn(asset);
        Mockito.when(finding.getComponent()).thenReturn(comp);
        Mockito.when(finding.getSeverityOverride()).thenReturn(null);

        return finding;
    }
}
