package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.prototype.vulnwatch.dto.PrototypeDataResetResponse;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class PrototypeDataResetServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("prototype_data_reset");

    @Test
    void cleanAllClearsDiscoveryModelsAfterSoftwareInstances() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                DATABASE.url(),
                DATABASE.username(),
                DATABASE.password()
        );
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        createMinimalSchema(jdbcTemplate);
        VulnerabilityIntelligenceService vulnerabilityIntelligenceService = mock(VulnerabilityIntelligenceService.class);
        PrototypeDataResetService service =
                new PrototypeDataResetService(vulnerabilityIntelligenceService, jdbcTemplate);

        Instant now = Instant.parse("2026-03-23T00:00:00Z");
        UUID tenantId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID ciId = UUID.randomUUID();
        UUID discoveryModelId = UUID.randomUUID();
        UUID softwareInstanceId = UUID.randomUUID();

        jdbcTemplate.update(
                "insert into tenants (id, created_at, name) values (?, ?, ?)",
                tenantId,
                Timestamp.from(now),
                "Default Tenant"
        );
        jdbcTemplate.update(
                """
                insert into assets (
                    id,
                    business_criticality,
                    created_at,
                    identifier,
                    name,
                    state,
                    type,
                    tenant_id
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                assetId,
                "HIGH",
                Timestamp.from(now),
                "host-001",
                "Host 001",
                "ACTIVE",
                "HOST",
                tenantId
        );
        jdbcTemplate.update(
                """
                insert into cis (
                    id,
                    tenant_id,
                    asset_id,
                    sys_id,
                    display_name,
                    business_criticality,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                ciId,
                tenantId,
                assetId,
                "ci-001",
                "Host 001",
                "HIGH",
                Timestamp.from(now),
                Timestamp.from(now)
        );
        jdbcTemplate.update(
                """
                insert into discovery_models (
                    id,
                    tenant_id,
                    primary_key,
                    approved,
                    low_confidence,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?, ?)
                """,
                discoveryModelId,
                tenantId,
                "sn-host-001",
                true,
                false,
                Timestamp.from(now),
                Timestamp.from(now)
        );
        jdbcTemplate.update(
                """
                insert into software_instances (
                    id,
                    tenant_id,
                    ci_id,
                    discovery_model_id,
                    display_name,
                    normalized_product,
                    source_system,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                softwareInstanceId,
                tenantId,
                ciId,
                discoveryModelId,
                "OpenSSL",
                "openssl",
                "SERVICENOW",
                Timestamp.from(now),
                Timestamp.from(now)
        );

        PrototypeDataResetResponse response = service.cleanAll();

        assertEquals(1L, response.deletedRows().get("software_instances"));
        assertEquals(1L, response.deletedRows().get("discovery_models"));
        assertEquals(0L, tableCount(jdbcTemplate, "software_instances"));
        assertEquals(0L, tableCount(jdbcTemplate, "discovery_models"));
        assertEquals(0L, tableCount(jdbcTemplate, "cis"));
        assertEquals(0L, tableCount(jdbcTemplate, "assets"));
        verify(vulnerabilityIntelligenceService).resetReadModelCaches();
    }

    private void createMinimalSchema(JdbcTemplate jdbcTemplate) {
        jdbcTemplate.execute("""
                create table tenants (
                    id uuid primary key,
                    created_at timestamp with time zone not null,
                    name varchar(255) not null
                )
                """);
        jdbcTemplate.execute("""
                create table assets (
                    id uuid primary key,
                    business_criticality varchar(255) not null,
                    created_at timestamp with time zone not null,
                    identifier varchar(255) not null,
                    name varchar(255) not null,
                    state varchar(255) not null,
                    type varchar(255) not null,
                    tenant_id uuid not null references tenants(id)
                )
                """);
        jdbcTemplate.execute("""
                create table cis (
                    id uuid primary key,
                    tenant_id uuid not null references tenants(id),
                    asset_id uuid not null references assets(id),
                    sys_id varchar(255) not null,
                    display_name varchar(255) not null,
                    business_criticality varchar(32) not null,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table discovery_models (
                    id uuid primary key,
                    tenant_id uuid not null references tenants(id),
                    primary_key varchar(500) not null,
                    approved boolean not null default false,
                    low_confidence boolean not null default false,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table software_instances (
                    id uuid primary key,
                    tenant_id uuid not null references tenants(id),
                    ci_id uuid not null references cis(id),
                    discovery_model_id uuid references discovery_models(id),
                    display_name varchar(500) not null,
                    normalized_product varchar(255) not null,
                    source_system varchar(64) not null,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null
                )
                """);
    }

    private long tableCount(JdbcTemplate jdbcTemplate, String tableName) {
        Long count = jdbcTemplate.queryForObject("select count(*) from " + tableName, Long.class);
        return count == null ? 0L : count;
    }
}
