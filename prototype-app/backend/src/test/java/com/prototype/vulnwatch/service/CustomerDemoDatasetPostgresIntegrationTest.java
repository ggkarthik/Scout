package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class CustomerDemoDatasetPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("customer_demo_dataset");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private CustomerDemoDatasetService datasetService;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void seedsCompleteDatasetIdempotentlyInsideTheSelectedTenant() {
        Tenant tenant = tenantService.getDefaultTenant();

        var first = datasetService.seed(tenant);
        var second = datasetService.seed(tenant);

        assertEquals(first, second);
        assertEquals(6, first.assets());
        assertEquals(6, first.sboms());
        assertEquals(24, first.components());
        assertEquals(18, first.findings());
        assertEquals(8, first.cves());
        assertEquals(2, first.campaigns());
        assertEquals(2, first.aiBoms());
        assertEquals(8, first.aiComponents());
        assertEquals(5, first.aiFindings());
        assertEquals(2, first.cboms());
        assertEquals(8, first.cbomComponents());
        assertEquals(9, first.cbomFindings());

        tenantSchemaExecutionService.run(tenant, () -> {
            assertEquals(6, count("assets"));
            assertEquals(6, count("sbom_uploads"));
            assertEquals(10, count("bom_ingestion_records"));
            assertEquals(16, count("bom_components"));
            assertEquals(16, count("bom_component_evidence"));
            assertEquals(5, count("bom_component_vulnerability_links"));
            assertEquals(5, count("bom_component_workflows"));
            assertEquals(8, count("cbom_components"));
            assertEquals(9, count("cbom_risk_findings"));
            assertEquals(2, count("cbom_posture_summary"));
            assertEquals(24, count("inventory_components"));
            assertEquals(18, count("findings"));
            assertEquals(18, count("finding_events"));
            assertEquals(18, count("finding_comments"));
            assertEquals(8, count("org_cve_records"));
            assertEquals(4, count("fix_records"));
            assertEquals(2, count("campaigns"));
            assertEquals(4, count("campaign_vulnerabilities"));
            assertEquals(5, count("audit_events"));
        });
    }

    private int count(String table) {
        return jdbcTemplate.queryForObject("SELECT count(*) FROM " + table, Integer.class);
    }
}
