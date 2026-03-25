package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.PrototypeDataResetResponse;
import java.time.Instant;
import java.util.List;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Locale;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@Service
public class PrototypeDataResetService {

    private static final List<String> TABLES_TO_CLEAR = List.of(
            "finding_suggestions",
            "finding_comments",
            "finding_events",
            "finding_delta_queue",
            "investigation_activities",
            "investigation_attachments",
            "investigations",
            "applicability_assessments",
            "findings",
            "component_vulnerability_states",
            "org_cve_records",
            "dashboard_noise_reduction_projection",
            "software_inventory_items",
            "inventory_component_cpe_map",
            "software_instances",
            "inventory_components",
            "software_identity_summary",
            "software_eol_mapping",
            "eol_release",
            "eol_product_catalog",
            "quality_issue_projection",
            "sbom_uploads",
            "discovery_models",
            "ci_aliases",
            "cis",
            "assets",
            "vex_assertions",
            "vulnerability_intel_summary_sources",
            "vulnerability_intel_summary",
            "vulnerability_threat_overlays",
            "vulnerability_source_context",
            "vulnerability_config_expr",
            "vulnerability_intel_observations",
            "vulnerability_rules",
            "vulnerability_targets",
            "vulnerabilities",
            "identity_links",
            "software_identifiers",
            "software_identities",
            "cpe_dim",
            "sync_runs"
    );

    private final VulnerabilityIntelligenceService vulnerabilityIntelligenceService;
    private final JdbcTemplate jdbcTemplate;

    public PrototypeDataResetService(
            VulnerabilityIntelligenceService vulnerabilityIntelligenceService,
            @Qualifier("prototypeResetJdbcTemplate")
            JdbcTemplate jdbcTemplate
    ) {
        this.vulnerabilityIntelligenceService = vulnerabilityIntelligenceService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional(transactionManager = "prototypeResetTransactionManager")
    public PrototypeDataResetResponse cleanAll() {
        Map<String, Long> deletedRows = new LinkedHashMap<>();
        boolean cascadeTruncate = usesCascadeTruncate();
        for (String tableName : TABLES_TO_CLEAR) {
            deletedRows.put(tableName, tableCount(tableName));
        }

        for (String tableName : TABLES_TO_CLEAR) {
            truncateOrDeleteTable(tableName, cascadeTruncate);
        }

        refreshReadModelCachesAfterCommit();
        return new PrototypeDataResetResponse(deletedRows, Instant.now());
    }

    private long tableCount(String tableName) {
        if (!tableExists(tableName)) {
            return 0L;
        }
        Long count = jdbcTemplate.queryForObject("select count(*) from " + tableName, Long.class);
        return count == null ? 0L : count;
    }

    private void truncateOrDeleteTable(String tableName, boolean cascadeTruncate) {
        if (!tableExists(tableName)) {
            return;
        }
        try {
            jdbcTemplate.execute(truncateStatement(tableName, cascadeTruncate));
        } catch (DataAccessException truncateError) {
            try {
                jdbcTemplate.update("delete from " + tableName);
            } catch (DataAccessException deleteError) {
                throw new IllegalStateException("Failed to reset table " + tableName, deleteError);
            }
        }
    }

    private boolean usesCascadeTruncate() {
        try {
            String databaseProductName = jdbcTemplate.execute(
                    (ConnectionCallback<String>) connection -> connection.getMetaData().getDatabaseProductName()
            );
            return databaseProductName != null
                    && databaseProductName.toLowerCase(Locale.ROOT).contains("postgresql");
        } catch (DataAccessException databaseError) {
            return false;
        }
    }

    private String truncateStatement(String tableName, boolean cascadeTruncate) {
        if (cascadeTruncate) {
            return "truncate table " + tableName + " restart identity cascade";
        }
        return "truncate table " + tableName;
    }

    private boolean tableExists(String tableName) {
        Long present = jdbcTemplate.queryForObject(
                "select count(*) from information_schema.tables where lower(table_name) = ?",
                Long.class,
                tableName.toLowerCase(Locale.ROOT)
        );
        return present != null && present > 0L;
    }

    private void refreshReadModelCachesAfterCommit() {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            vulnerabilityIntelligenceService.resetReadModelCaches();
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                vulnerabilityIntelligenceService.resetReadModelCaches();
            }
        });
    }
}
