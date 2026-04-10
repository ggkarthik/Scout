package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import java.util.List;
import org.junit.jupiter.api.Test;

class ServiceNowCmdbSyncServiceTest {

    @Test
    void candidatePageSizesReduceLargeConfiguredPageSizes() {
        assertEquals(List.of(1000, 250, 100, 25), ServiceNowCmdbSyncService.candidatePageSizes(1000));
    }

    @Test
    void candidatePageSizesAvoidDuplicateFallbacks() {
        assertEquals(List.of(50, 25), ServiceNowCmdbSyncService.candidatePageSizes(50));
        assertEquals(List.of(25), ServiceNowCmdbSyncService.candidatePageSizes(25));
    }

    @Test
    void displayValueModeOnlyUsesDisplayValuesForInstallTable() {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config = new ServiceNowCmdbConfigService.ServiceNowRuntimeConfig(
                "https://example.service-now.com",
                ServiceNowAuthType.BASIC,
                "admin",
                "secret",
                "cmdb_sam_sw_install",
                "cmdb_sam_sw_discovery_model",
                "cmdb_ci",
                "",
                "",
                "sys_id",
                "sys_id",
                1000,
                true,
                false,
                1440
        );

        assertEquals("all", ServiceNowCmdbSyncService.displayValueModeForTable(config, "cmdb_sam_sw_install"));
        assertEquals("false", ServiceNowCmdbSyncService.displayValueModeForTable(config, "cmdb_sam_sw_discovery_model"));
        assertEquals("false", ServiceNowCmdbSyncService.displayValueModeForTable(config, "cmdb_ci"));
    }
}
