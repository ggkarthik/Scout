package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.prototype.vulnwatch.dto.AgentTaskMetaDto;
import com.prototype.vulnwatch.dto.EolAnalysisResponse;
import com.prototype.vulnwatch.dto.EolAnalysisResultDto;
import com.prototype.vulnwatch.dto.FalsePositiveAnalysisResponse;
import com.prototype.vulnwatch.dto.FalsePositiveResultDto;
import com.prototype.vulnwatch.dto.InventoryResolutionResponse;
import com.prototype.vulnwatch.dto.ResolvedInventorySoftwareDto;
import java.util.List;
import org.junit.jupiter.api.Test;

class InvestigationAgentServiceFallbackTest {

    @Test
    void inventoryFallbackReturnsLowWhenNoAssetsMatch() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicInventoryMeta(
                new InventoryResolutionResponse(List.of(), 0));

        assertEquals("LOW", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void inventoryFallbackReturnsMediumWhenAssetsMatchWithoutResolvedSoftware() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicInventoryMeta(
                new InventoryResolutionResponse(List.of(), 4));

        assertEquals("MEDIUM", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void inventoryFallbackReturnsHighWhenAssetsAndResolvedSoftwareExist() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicInventoryMeta(
                new InventoryResolutionResponse(
                        List.of(new ResolvedInventorySoftwareDto(
                                "sw-1", "nginx", "NGINX", "1.25.4", List.of(), null, null, null, null)),
                        4));

        assertEquals("HIGH", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void falsePositiveFallbackReturnsLowWhenNoRowsExist() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicFpMeta(
                new FalsePositiveAnalysisResponse(List.of()));

        assertEquals("LOW", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void falsePositiveFallbackReturnsMediumWithoutVendorVexData() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicFpMeta(
                new FalsePositiveAnalysisResponse(List.of(new FalsePositiveResultDto(
                        "fp-1", "openssl", "3.0.0", false, 0, null, null,
                        "Needs review", "No vendor evidence", "warning"))));

        assertEquals("MEDIUM", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void falsePositiveFallbackReturnsHighWithVendorVexData() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicFpMeta(
                new FalsePositiveAnalysisResponse(List.of(new FalsePositiveResultDto(
                        "fp-1", "openssl", "3.0.0", true, 3, "Vendor advisory", null,
                        "Cleared", "VEX says not affected", "success"))));

        assertEquals("HIGH", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void eolFallbackReturnsLowWhenNoSoftwareRowsExist() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicEolMeta(
                new EolAnalysisResponse(List.of()));

        assertEquals("LOW", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void eolFallbackReturnsMediumWhenAllSoftwareIsSupported() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicEolMeta(
                new EolAnalysisResponse(List.of(new EolAnalysisResultDto(
                        "eol-1", "nginx", "NGINX", "1.25.4", "Supported", null, null, null))));

        assertEquals("MEDIUM", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    @Test
    void eolFallbackReturnsHighWhenLifecycleDataFlagsRisk() {
        AgentTaskMetaDto meta = InvestigationAgentService.algorithmicEolMeta(
                new EolAnalysisResponse(List.of(new EolAnalysisResultDto(
                        "eol-1", "nginx", "NGINX", "1.10.0", "End of Life", null, "2024-01-01", "Upgrade"))));

        assertEquals("HIGH", meta.confidence());
        assertReasoningLooksReal(meta);
    }

    private void assertReasoningLooksReal(AgentTaskMetaDto meta) {
        assertFalse(meta.reasoning() == null || meta.reasoning().isBlank());
        assertFalse(meta.reasoning().contains("<"));
        assertFalse(meta.reasoning().toLowerCase().contains("placeholder"));
    }
}
