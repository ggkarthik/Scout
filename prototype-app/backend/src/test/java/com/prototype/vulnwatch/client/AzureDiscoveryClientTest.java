package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceRecord;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class AzureDiscoveryClientTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final AzureDiscoveryClient client = new AzureDiscoveryClient(objectMapper);

    @Test
    void matchesRegion_returnsTrueWhenRegionListEmpty() {
        boolean matches = ReflectionTestUtils.invokeMethod(client, "matchesRegion", "eastus2", List.of());
        assertTrue(matches);
    }

    @Test
    void matchesRegion_filtersOutNonSelectedRegionCaseInsensitively() {
        boolean matchesSelected = ReflectionTestUtils.invokeMethod(client, "matchesRegion", "EastUS2", List.of("eastus2", "westus2"));
        boolean matchesUnselected = ReflectionTestUtils.invokeMethod(client, "matchesRegion", "northeurope", List.of("eastus2", "westus2"));

        assertTrue(matchesSelected);
        assertFalse(matchesUnselected);
    }

    @Test
    void matchesRegion_treatsBlankLocationAsAlwaysMatching() {
        boolean matches = ReflectionTestUtils.invokeMethod(client, "matchesRegion", null, List.of("eastus2"));
        assertTrue(matches);
    }

    @Test
    void toRecord_extractsResourceGroupAndTagsFromArmJson() throws Exception {
        JsonNode value = objectMapper.readTree("""
                {
                  "id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-1",
                  "name": "vm-1",
                  "type": "Microsoft.Compute/virtualMachines",
                  "location": "eastus2",
                  "kind": "",
                  "properties": { "provisioningState": "Succeeded" },
                  "tags": { "env": "prod" }
                }
                """);

        AzureResourceRecord record = ReflectionTestUtils.invokeMethod(client, "toRecord", "sub-1", value);

        assertEquals("sub-1", record.subscriptionId());
        assertEquals("vm-1", record.name());
        assertEquals("Microsoft.Compute/virtualMachines", record.resourceType());
        assertEquals("rg1", record.resourceGroup());
        assertEquals("eastus2", record.location());
        assertEquals("Succeeded", record.provisioningState());
        assertEquals("prod", record.tags().get("env"));
    }

    @Test
    void toRecord_fallsBackToTrailingIdSegmentWhenNameMissing() throws Exception {
        JsonNode value = objectMapper.readTree("""
                {
                  "id": "/subscriptions/sub-1/resourceGroups/rg1/providers/Microsoft.Compute/virtualMachines/vm-2"
                }
                """);

        AzureResourceRecord record = ReflectionTestUtils.invokeMethod(client, "toRecord", "sub-1", value);

        assertEquals("vm-2", record.name());
    }
}
