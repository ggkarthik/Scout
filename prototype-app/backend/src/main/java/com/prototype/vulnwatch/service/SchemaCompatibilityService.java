package com.prototype.vulnwatch.service;

import jakarta.annotation.PostConstruct;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class SchemaCompatibilityService {

    private static final Logger log = LoggerFactory.getLogger(SchemaCompatibilityService.class);

    private final JdbcTemplate jdbcTemplate;

    public SchemaCompatibilityService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @PostConstruct
    public void ensureCompatibilityColumns() {
        List<String> statements = List.of(
                "alter table if exists assets alter column \"type\" type varchar(32)",
                "alter table if exists assets alter column \"type\" varchar(32)",
                "alter table if exists findings alter column status type varchar(32)",
                "alter table if exists findings alter column status varchar(32)",
                "alter table if exists github_sbom_sources alter column asset_type type varchar(32)",
                "alter table if exists github_sbom_sources alter column asset_type varchar(32)",
                "alter table if exists assets add column if not exists service_name varchar(255)",
                "alter table if exists assets add column if not exists environment varchar(64)",
                "alter table if exists assets add column if not exists owner_team varchar(255)",
                "alter table if exists assets add column if not exists owner_email varchar(255)",
                "alter table if exists assets add column if not exists business_criticality varchar(32)",
                "alter table if exists assets add column if not exists state varchar(32)",
                "alter table if exists assets add column if not exists last_inventory_at timestamp with time zone",
                "alter table if exists assets add column if not exists last_cmdb_sync_at timestamp with time zone",
                "update assets set business_criticality='MEDIUM' where business_criticality is null",
                "update assets set state='ACTIVE' where state is null",

                "alter table if exists inventory_components add column if not exists software_identity_id uuid",
                "alter table if exists inventory_components add column if not exists component_status varchar(32)",
                "alter table if exists inventory_components add column if not exists component_digest varchar(120)",
                "alter table if exists inventory_components add column if not exists normalized_name varchar(500)",
                "alter table if exists inventory_components add column if not exists normalized_version varchar(255)",
                "alter table if exists inventory_components add column if not exists software_model_result varchar(500)",
                "alter table if exists inventory_components add column if not exists last_observed_at timestamp with time zone",
                "alter table if exists inventory_components add column if not exists retired_at timestamp with time zone",
                "update inventory_components set component_status='ACTIVE' where component_status is null",
                "update inventory_components set normalized_name=lower(package_name) where (normalized_name is null or trim(normalized_name)='') and package_name is not null",
                "update inventory_components set normalized_name='unknown' where normalized_name is null or trim(normalized_name)=''",
                "update inventory_components set normalized_version=lower(\"version\") where (normalized_version is null or trim(normalized_version)='') and \"version\" is not null",
                "update inventory_components set normalized_version='unknown' where normalized_version is null or trim(normalized_version)=''",
                "update inventory_components set software_model_result='UNRESOLVED' where software_model_result is null or trim(software_model_result)=''",
                "update inventory_components ic set software_model_result='MATCHED:' || lower((select sm.normalized_key from software_models sm where sm.id = ic.software_model_id)) where ic.software_model_id is not null",
                "update inventory_components set last_observed_at=ingested_at where last_observed_at is null and ingested_at is not null",
                "update inventory_components set last_observed_at=CURRENT_TIMESTAMP where last_observed_at is null",
                "create index if not exists idx_inventory_component_digest on inventory_components(component_digest)",

                "alter table if exists github_sbom_sources add column if not exists path varchar(1000)",
                "alter table if exists github_sbom_sources add column if not exists asset_type varchar(32)",
                "alter table if exists github_sbom_sources add column if not exists asset_name varchar(255)",
                "alter table if exists github_sbom_sources add column if not exists asset_identifier varchar(255)",
                "alter table if exists github_sbom_sources add column if not exists frequency varchar(32)",
                "alter table if exists github_sbom_sources add column if not exists interval_minutes integer",
                "alter table if exists github_sbom_sources add column if not exists enabled boolean",
                "update github_sbom_sources set path='dependency-graph/sbom' where path is null or trim(path)=''",
                "update github_sbom_sources set asset_type='APPLICATION' where asset_type is null or trim(asset_type)=''",
                "update github_sbom_sources set asset_name=owner || '/' || repo where asset_name is null or trim(asset_name)=''",
                "update github_sbom_sources set asset_identifier=lower('github:' || owner || '/' || repo) where asset_identifier is null or trim(asset_identifier)=''",
                "update github_sbom_sources set frequency='ONCE' where frequency is null or trim(frequency)=''",
                "update github_sbom_sources set interval_minutes=60 where interval_minutes is null",
                "update github_sbom_sources set enabled=true where enabled is null",

                "alter table if exists sbom_uploads add column if not exists status varchar(32)",
                "update sbom_uploads set status='SUCCESS' where status is null or trim(status)=''",

                "alter table if exists findings add column if not exists decision_state varchar(40)",
                "alter table if exists findings add column if not exists precedence_trace clob",
                "update findings set decision_state='AFFECTED' where decision_state is null and status in ('OPEN','SUPPRESSED','AUTO_CLOSED')",
                "update findings set decision_state='NOT_AFFECTED' where decision_state is null and status='RESOLVED'",
                "update findings set decision_state='NEEDS_REVIEW' where decision_state is null",

                "alter table if exists vulnerability_targets add column if not exists constraint_type varchar(40)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_part varchar(40)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_vendor varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_product varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_version varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_update varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_edition varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_language varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_sw_edition varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_target_sw varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_target_hw varchar(255)",
                "alter table if exists vulnerability_targets add column if not exists qualifier_other varchar(255)",
                "update vulnerability_targets set constraint_type='EXACT' where constraint_type is null and version_exact is not null and trim(version_exact)<>''",
                "update vulnerability_targets set constraint_type='INTRODUCED_FIXED' where constraint_type is null and ((introduced is not null and trim(introduced)<>'') or (fixed is not null and trim(fixed)<>''))",
                "update vulnerability_targets set constraint_type='RANGE' where constraint_type is null and ((version_start is not null and trim(version_start)<>'') or (version_end is not null and trim(version_end)<>''))",
                "update vulnerability_targets set constraint_type='NONE' where constraint_type is null",

                "create table if not exists vulnerability_config_expr ("
                        + "id uuid not null primary key,"
                        + "vulnerability_id uuid not null,"
                        + "source varchar(40) not null,"
                        + "config_index integer not null,"
                        + "node_path varchar(1000) not null,"
                        + "parent_path varchar(1000),"
                        + "\"operator\" varchar(32),"
                        + "negate boolean not null,"
                        + "match_criteria_count integer,"
                        + "child_node_count integer,"
                        + "expr_json clob,"
                        + "created_at timestamp with time zone not null"
                        + ")",
                "create index if not exists idx_vuln_cfg_expr_vuln on vulnerability_config_expr(vulnerability_id)",
                "create index if not exists idx_vuln_cfg_expr_source_cfg on vulnerability_config_expr(source, config_index)",

                "create table if not exists vulnerability_intel_observations ("
                        + "id uuid not null primary key,"
                        + "vulnerability_id uuid not null,"
                        + "source_system varchar(80) not null,"
                        + "source_record_id varchar(255) not null,"
                        + "source_url varchar(1200),"
                        + "title varchar(255),"
                        + "description clob,"
                        + "severity varchar(40),"
                        + "cvss_score double precision,"
                        + "cvss_vector varchar(300),"
                        + "epss_score double precision,"
                        + "in_kev boolean,"
                        + "vuln_status varchar(120),"
                        + "cwe_ids varchar(2000),"
                        + "references_json clob,"
                        + "source_identifier varchar(255),"
                        + "published_at timestamp with time zone,"
                        + "last_modified_at timestamp with time zone,"
                        + "raw_payload clob,"
                        + "payload_hash varchar(128),"
                        + "observed_at timestamp with time zone not null,"
                        + "last_seen_at timestamp with time zone not null,"
                        + "created_at timestamp with time zone not null,"
                        + "updated_at timestamp with time zone not null"
                        + ")",
                "create unique index if not exists uk_vuln_intel_observation_source_record on vulnerability_intel_observations(vulnerability_id, source_system, source_record_id)",
                "create index if not exists idx_vuln_intel_obs_vulnerability on vulnerability_intel_observations(vulnerability_id)",
                "create index if not exists idx_vuln_intel_obs_source on vulnerability_intel_observations(source_system)",
                "create index if not exists idx_vuln_intel_obs_last_seen on vulnerability_intel_observations(last_seen_at)",

                "alter table if exists risk_policies add column if not exists asset_critical_risk_boost double precision",
                "alter table if exists risk_policies add column if not exists asset_high_risk_boost double precision",
                "alter table if exists risk_policies add column if not exists asset_medium_risk_boost double precision",
                "alter table if exists risk_policies add column if not exists asset_low_risk_boost double precision",
                "alter table if exists risk_policies add column if not exists critical_sla_days integer",
                "alter table if exists risk_policies add column if not exists high_sla_days integer",
                "alter table if exists risk_policies add column if not exists medium_sla_days integer",
                "alter table if exists risk_policies add column if not exists low_sla_days integer",
                "alter table if exists risk_policies add column if not exists asset_critical_sla_multiplier double precision",
                "alter table if exists risk_policies add column if not exists asset_high_sla_multiplier double precision",
                "alter table if exists risk_policies add column if not exists asset_medium_sla_multiplier double precision",
                "alter table if exists risk_policies add column if not exists asset_low_sla_multiplier double precision",
                "alter table if exists risk_policies add column if not exists auto_close_enabled boolean",
                "alter table if exists risk_policies add column if not exists auto_close_asset_identifier varchar(255)",
                "alter table if exists risk_policies add column if not exists auto_close_after_days integer",
                "update risk_policies set asset_critical_risk_boost=1.5 where asset_critical_risk_boost is null",
                "update risk_policies set asset_high_risk_boost=1.0 where asset_high_risk_boost is null",
                "update risk_policies set asset_medium_risk_boost=0.5 where asset_medium_risk_boost is null",
                "update risk_policies set asset_low_risk_boost=0.0 where asset_low_risk_boost is null",
                "update risk_policies set critical_sla_days=7 where critical_sla_days is null",
                "update risk_policies set high_sla_days=14 where high_sla_days is null",
                "update risk_policies set medium_sla_days=30 where medium_sla_days is null",
                "update risk_policies set low_sla_days=60 where low_sla_days is null",
                "update risk_policies set asset_critical_sla_multiplier=0.5 where asset_critical_sla_multiplier is null",
                "update risk_policies set asset_high_sla_multiplier=0.75 where asset_high_sla_multiplier is null",
                "update risk_policies set asset_medium_sla_multiplier=1.0 where asset_medium_sla_multiplier is null",
                "update risk_policies set asset_low_sla_multiplier=1.25 where asset_low_sla_multiplier is null",
                "update risk_policies set auto_close_enabled=false where auto_close_enabled is null",
                "update risk_policies set auto_close_after_days=0 where auto_close_after_days is null");

        for (String statement : statements) {
            try {
                jdbcTemplate.execute(statement);
            } catch (Exception ex) {
                log.warn("Schema compatibility statement failed: {}", statement, ex);
            }
        }
    }
}
