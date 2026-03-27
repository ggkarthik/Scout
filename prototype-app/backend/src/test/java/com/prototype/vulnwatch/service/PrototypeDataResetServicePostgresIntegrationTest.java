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
        VulnerabilityIntelSummaryService vulnerabilityIntelSummaryService = mock(VulnerabilityIntelSummaryService.class);
        PrototypeDataResetService service =
                new PrototypeDataResetService(vulnerabilityIntelSummaryService, jdbcTemplate);

        Instant now = Instant.parse("2026-03-23T00:00:00Z");
        UUID tenantId = UUID.randomUUID();
        UUID assetId = UUID.randomUUID();
        UUID ciId = UUID.randomUUID();
        UUID discoveryModelId = UUID.randomUUID();
        UUID softwareInstanceId = UUID.randomUUID();
        UUID vulnerabilityId = UUID.randomUUID();
        UUID eolProductId = UUID.randomUUID();
        UUID eolReleaseId = UUID.randomUUID();
        UUID observationId = UUID.randomUUID();
        UUID sourceContextId = UUID.randomUUID();
        UUID threatOverlayId = UUID.randomUUID();
        long investigationId = 1L;
        long investigationActivityId = 10L;

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
        jdbcTemplate.update(
                """
                insert into eol_product_catalog (
                    id,
                    slug,
                    product_name,
                    display_name,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?)
                """,
                eolProductId,
                "openssl",
                "openssl",
                "OpenSSL",
                Timestamp.from(now),
                Timestamp.from(now)
        );
        jdbcTemplate.update(
                """
                insert into eol_release (
                    id,
                    product_slug,
                    cycle,
                    release_date,
                    eol_date,
                    latest,
                    latest_release,
                    is_eol,
                    created_at,
                    updated_at
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                eolReleaseId,
                "openssl",
                "3.0",
                java.sql.Date.valueOf("2024-01-01"),
                java.sql.Date.valueOf("2026-01-01"),
                "3.0.15",
                "3.0.15",
                false,
                Timestamp.from(now),
                Timestamp.from(now)
        );
        jdbcTemplate.update(
                """
                insert into vulnerabilities (
                    id,
                    source,
                    published_at,
                    last_modified_at
                ) values (?, ?, ?, ?)
                """,
                vulnerabilityId,
                "NVD",
                Timestamp.from(now),
                Timestamp.from(now)
        );
        jdbcTemplate.update(
                """
                insert into vulnerability_intel_observations (
                    id,
                    vulnerability_id,
                    observed_at
                ) values (?, ?, ?)
                """,
                observationId,
                vulnerabilityId,
                Timestamp.from(now)
        );
        jdbcTemplate.update(
                """
                insert into vulnerability_source_context (
                    id,
                    vulnerability_id,
                    observation_id
                ) values (?, ?, ?)
                """,
                sourceContextId,
                vulnerabilityId,
                observationId
        );
        jdbcTemplate.update(
                """
                insert into vulnerability_threat_overlays (
                    id,
                    vulnerability_id
                ) values (?, ?)
                """,
                threatOverlayId,
                vulnerabilityId
        );
        jdbcTemplate.update(
                """
                insert into investigations (
                    id,
                    status,
                    created_at,
                    updated_at,
                    tenant_id,
                    vulnerability_id
                ) values (?, ?, ?, ?, ?, ?)
                """,
                investigationId,
                "OPEN",
                Timestamp.from(now),
                Timestamp.from(now),
                tenantId,
                vulnerabilityId
        );
        jdbcTemplate.update(
                """
                insert into investigation_activities (
                    id,
                    activity_type,
                    created_at,
                    investigation_id
                ) values (?, ?, ?, ?)
                """,
                investigationActivityId,
                "CREATED",
                Timestamp.from(now),
                investigationId
        );

        PrototypeDataResetResponse response = service.cleanAll();

        assertEquals(1L, response.deletedRows().get("software_instances"));
        assertEquals(1L, response.deletedRows().get("discovery_models"));
        assertEquals(1L, response.deletedRows().get("investigations"));
        assertEquals(1L, response.deletedRows().get("investigation_activities"));
        assertEquals(1L, response.deletedRows().get("vulnerability_source_context"));
        assertEquals(1L, response.deletedRows().get("vulnerability_threat_overlays"));
        assertEquals(1L, response.deletedRows().get("eol_release"));
        assertEquals(1L, response.deletedRows().get("eol_product_catalog"));
        assertEquals(0L, tableCount(jdbcTemplate, "software_instances"));
        assertEquals(0L, tableCount(jdbcTemplate, "discovery_models"));
        assertEquals(0L, tableCount(jdbcTemplate, "investigations"));
        assertEquals(0L, tableCount(jdbcTemplate, "investigation_activities"));
        assertEquals(0L, tableCount(jdbcTemplate, "vulnerability_source_context"));
        assertEquals(0L, tableCount(jdbcTemplate, "vulnerability_threat_overlays"));
        assertEquals(0L, tableCount(jdbcTemplate, "vulnerability_intel_observations"));
        assertEquals(0L, tableCount(jdbcTemplate, "vulnerabilities"));
        assertEquals(0L, tableCount(jdbcTemplate, "cis"));
        assertEquals(0L, tableCount(jdbcTemplate, "assets"));
        assertEquals(0L, tableCount(jdbcTemplate, "eol_release"));
        assertEquals(0L, tableCount(jdbcTemplate, "eol_product_catalog"));
        verify(vulnerabilityIntelSummaryService).resetReadModelCaches();
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
        jdbcTemplate.execute("""
                create table eol_product_catalog (
                    id uuid primary key,
                    slug varchar(200) not null unique,
                    product_name varchar(255) not null,
                    display_name varchar(255) not null,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table eol_release (
                    id uuid primary key,
                    product_slug varchar(200) not null references eol_product_catalog(slug) on delete cascade,
                    cycle varchar(100) not null,
                    release_date date,
                    eol_date date,
                    latest varchar(100),
                    latest_release varchar(100),
                    is_eol boolean,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table vulnerabilities (
                    id uuid primary key,
                    source varchar(32) not null,
                    published_at timestamp with time zone not null,
                    last_modified_at timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table vulnerability_intel_observations (
                    id uuid primary key,
                    vulnerability_id uuid not null references vulnerabilities(id),
                    observed_at timestamp with time zone not null
                )
                """);
        jdbcTemplate.execute("""
                create table vulnerability_source_context (
                    id uuid primary key,
                    vulnerability_id uuid not null references vulnerabilities(id),
                    observation_id uuid not null references vulnerability_intel_observations(id)
                )
                """);
        jdbcTemplate.execute("""
                create table vulnerability_threat_overlays (
                    id uuid primary key,
                    vulnerability_id uuid not null references vulnerabilities(id)
                )
                """);
        jdbcTemplate.execute("""
                create table investigations (
                    id bigint primary key,
                    status varchar(50) not null,
                    created_at timestamp with time zone not null,
                    updated_at timestamp with time zone not null,
                    tenant_id uuid not null references tenants(id),
                    vulnerability_id uuid not null references vulnerabilities(id)
                )
                """);
        jdbcTemplate.execute("""
                create table investigation_activities (
                    id bigint primary key,
                    activity_type varchar(50) not null,
                    created_at timestamp with time zone not null,
                    investigation_id bigint not null references investigations(id)
                )
                """);
    }

    private long tableCount(JdbcTemplate jdbcTemplate, String tableName) {
        Long count = jdbcTemplate.queryForObject("select count(*) from " + tableName, Long.class);
        return count == null ? 0L : count;
    }
}
