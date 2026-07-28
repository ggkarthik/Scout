package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import java.util.HashSet;
import org.junit.jupiter.api.Test;

class AzurePolicyPermissionMatrixTest {

    private final AzurePolicyPermissionMatrix matrix =
            new AzurePolicyPermissionMatrix(new AiSecurityPolicyRegistry());

    @Test
    void coversEveryRuntimeFamilyAndShippedAzurePolicy() {
        assertEquals(AiSecurityAzureConnectorService.RESOURCE_FAMILIES, matrix.resourceFamilies());
        assertEquals(8, matrix.requirementsReport().policies().size());
        assertTrue(matrix.requirementsReport().policies().stream()
                .allMatch(policy -> !policy.resourceFamilies().isEmpty()));
    }

    @Test
    void generatedRoleContainsOnlyDistinctAllowedActions() {
        var role = matrix.roleTemplate();
        assertFalse(role.actions().isEmpty());
        assertEquals(role.actions().size(), new HashSet<>(role.actions()).size());
        assertTrue(role.notActions().contains(
                "Microsoft.Search/searchServices/listAdminKeys/action"));
        assertTrue(role.notActions().contains(
                "Microsoft.Search/searchServices/indexes/documents/read"));
        assertTrue(role.actions().stream().noneMatch(role.notActions()::contains));
    }

    @Test
    void familyReportPreservesExactApiVersionRoleAndAction() {
        var search = matrix.family("AZURE_SEARCH_DATA_SOURCES");
        assertEquals("2024-07-01", search.apiVersion());
        assertTrue(search.role().contains("custom role"));
        assertEquals(
                java.util.List.of("Microsoft.Search/searchServices/dataSources/read"),
                search.actions());
    }
}
