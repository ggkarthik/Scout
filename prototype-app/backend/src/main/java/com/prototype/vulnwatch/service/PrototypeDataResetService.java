package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.PrototypeDataResetResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.CpeDimRepository;
import com.prototype.vulnwatch.repo.FindingCommentRepository;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentifierRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import com.prototype.vulnwatch.repo.SoftwareInventoryItemRepository;
import com.prototype.vulnwatch.repo.SoftwareModelRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.repo.VulnerabilityConfigExprRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummaryRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummarySourceRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRuleRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.jdbc.core.JdbcTemplate;

@Service
public class PrototypeDataResetService {

    private final FindingCommentRepository findingCommentRepository;
    private final FindingEventRepository findingEventRepository;
    private final FindingRepository findingRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final SoftwareInventoryItemRepository softwareInventoryItemRepository;
    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final SbomUploadRepository sbomUploadRepository;
    private final AssetRepository assetRepository;
    private final VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository;
    private final VulnerabilityIntelSummaryRepository vulnerabilityIntelSummaryRepository;
    private final VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository;
    private final VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;
    private final VulnerabilityRuleRepository vulnerabilityRuleRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final IdentityLinkRepository identityLinkRepository;
    private final SoftwareIdentifierRepository softwareIdentifierRepository;
    private final SoftwareIdentityRepository softwareIdentityRepository;
    private final SoftwareModelRepository softwareModelRepository;
    private final CpeDimRepository cpeDimRepository;
    private final SyncRunRepository syncRunRepository;
    private final VulnerabilityIntelligenceService vulnerabilityIntelligenceService;
    private final JdbcTemplate jdbcTemplate;

    public PrototypeDataResetService(
            FindingCommentRepository findingCommentRepository,
            FindingEventRepository findingEventRepository,
            FindingRepository findingRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            SoftwareInventoryItemRepository softwareInventoryItemRepository,
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            InventoryComponentRepository inventoryComponentRepository,
            SbomUploadRepository sbomUploadRepository,
            AssetRepository assetRepository,
            VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository,
            VulnerabilityIntelSummaryRepository vulnerabilityIntelSummaryRepository,
            VulnerabilityConfigExprRepository vulnerabilityConfigExprRepository,
            VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository,
            VulnerabilityRuleRepository vulnerabilityRuleRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            VulnerabilityRepository vulnerabilityRepository,
            IdentityLinkRepository identityLinkRepository,
            SoftwareIdentifierRepository softwareIdentifierRepository,
            SoftwareIdentityRepository softwareIdentityRepository,
            SoftwareModelRepository softwareModelRepository,
            CpeDimRepository cpeDimRepository,
            SyncRunRepository syncRunRepository,
            VulnerabilityIntelligenceService vulnerabilityIntelligenceService,
            JdbcTemplate jdbcTemplate
    ) {
        this.findingCommentRepository = findingCommentRepository;
        this.findingEventRepository = findingEventRepository;
        this.findingRepository = findingRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.softwareInventoryItemRepository = softwareInventoryItemRepository;
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.sbomUploadRepository = sbomUploadRepository;
        this.assetRepository = assetRepository;
        this.vulnerabilityIntelSummarySourceRepository = vulnerabilityIntelSummarySourceRepository;
        this.vulnerabilityIntelSummaryRepository = vulnerabilityIntelSummaryRepository;
        this.vulnerabilityConfigExprRepository = vulnerabilityConfigExprRepository;
        this.vulnerabilityIntelObservationRepository = vulnerabilityIntelObservationRepository;
        this.vulnerabilityRuleRepository = vulnerabilityRuleRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.identityLinkRepository = identityLinkRepository;
        this.softwareIdentifierRepository = softwareIdentifierRepository;
        this.softwareIdentityRepository = softwareIdentityRepository;
        this.softwareModelRepository = softwareModelRepository;
        this.cpeDimRepository = cpeDimRepository;
        this.syncRunRepository = syncRunRepository;
        this.vulnerabilityIntelligenceService = vulnerabilityIntelligenceService;
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    public PrototypeDataResetResponse cleanAll() {
        Map<String, Long> deletedRows = new LinkedHashMap<>();
        deletedRows.put("finding_suggestions", tableCount("finding_suggestions"));
        deletedRows.put("finding_comments", findingCommentRepository.count());
        deletedRows.put("finding_events", findingEventRepository.count());
        deletedRows.put("findings", findingRepository.count());
        deletedRows.put("component_vulnerability_state", componentVulnerabilityStateRepository.count());
        deletedRows.put("org_cve_records", orgCveRecordRepository.count());
        deletedRows.put("software_inventory_items", softwareInventoryItemRepository.count());
        deletedRows.put("inventory_component_cpe_map", inventoryComponentCpeMapRepository.count());
        deletedRows.put("inventory_components", inventoryComponentRepository.count());
        deletedRows.put("sbom_uploads", sbomUploadRepository.count());
        deletedRows.put("assets", assetRepository.count());
        deletedRows.put("vulnerability_intel_summary_sources", vulnerabilityIntelSummarySourceRepository.count());
        deletedRows.put("vulnerability_intel_summary", vulnerabilityIntelSummaryRepository.count());
        deletedRows.put("vulnerability_config_expr", vulnerabilityConfigExprRepository.count());
        deletedRows.put("vulnerability_intel_observations", vulnerabilityIntelObservationRepository.count());
        deletedRows.put("vulnerability_rules", vulnerabilityRuleRepository.count());
        deletedRows.put("vulnerability_targets", vulnerabilityTargetRepository.count());
        deletedRows.put("vulnerabilities", vulnerabilityRepository.count());
        deletedRows.put("identity_links", identityLinkRepository.count());
        deletedRows.put("software_identifiers", softwareIdentifierRepository.count());
        deletedRows.put("software_identities", softwareIdentityRepository.count());
        deletedRows.put("software_models", softwareModelRepository.count());
        deletedRows.put("cpe_dim", cpeDimRepository.count());
        deletedRows.put("sync_runs", syncRunRepository.count());

        boolean h2Database = isH2Database();
        if (h2Database) {
            jdbcTemplate.execute("SET REFERENTIAL_INTEGRITY FALSE");
        }
        try {
            truncateOrDeleteTable("finding_suggestions");
            truncateOrDeleteTable("finding_comments");
            truncateOrDeleteTable("finding_events");
            truncateOrDeleteTable("findings");
            truncateOrDeleteTable("component_vulnerability_state");
            truncateOrDeleteTable("org_cve_records");
            truncateOrDeleteTable("software_inventory_items");
            truncateOrDeleteTable("inventory_component_cpe_map");
            truncateOrDeleteTable("inventory_components");
            truncateOrDeleteTable("sbom_uploads");
            truncateOrDeleteTable("assets");
            truncateOrDeleteTable("vulnerability_intel_summary_sources");
            truncateOrDeleteTable("vulnerability_intel_summary");
            truncateOrDeleteTable("vulnerability_config_expr");
            truncateOrDeleteTable("vulnerability_intel_observations");
            truncateOrDeleteTable("vulnerability_rules");
            truncateOrDeleteTable("vulnerability_targets");
            truncateOrDeleteTable("vulnerabilities");
            truncateOrDeleteTable("identity_links");
            truncateOrDeleteTable("software_identifiers");
            truncateOrDeleteTable("software_identities");
            truncateOrDeleteTable("software_models");
            truncateOrDeleteTable("cpe_dim");
            truncateOrDeleteTable("sync_runs");
        } finally {
            if (h2Database) {
                jdbcTemplate.execute("SET REFERENTIAL_INTEGRITY TRUE");
            }
        }

        vulnerabilityIntelligenceService.resetReadModelCaches();
        return new PrototypeDataResetResponse(deletedRows, Instant.now());
    }

    private long tableCount(String tableName) {
        if (!tableExists(tableName)) {
            return 0L;
        }
        Long count = jdbcTemplate.queryForObject("select count(*) from " + tableName, Long.class);
        return count == null ? 0L : count;
    }

    private void truncateOrDeleteTable(String tableName) {
        if (!tableExists(tableName)) {
            return;
        }
        try {
            jdbcTemplate.execute("truncate table " + tableName);
        } catch (DataAccessException ignored) {
            jdbcTemplate.update("delete from " + tableName);
        }
    }

    private boolean tableExists(String tableName) {
        Long present = jdbcTemplate.queryForObject(
                "select count(*) from information_schema.tables where lower(table_name) = ?",
                Long.class,
                tableName.toLowerCase(Locale.ROOT)
        );
        return present != null && present > 0L;
    }

    private boolean isH2Database() {
        String productName = jdbcTemplate.execute((ConnectionCallback<String>) connection ->
                connection.getMetaData().getDatabaseProductName());
        if (productName == null) {
            return false;
        }
        return productName.toLowerCase(Locale.ROOT).contains("h2");
    }
}
