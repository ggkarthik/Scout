package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class QualityIssueRefreshService {

    private final TenantRepository tenantRepository;
    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final IngestionQualityIssueBuilder ingestionQualityIssueBuilder;
    private final NormalizationQualityIssueBuilder normalizationQualityIssueBuilder;
    private final CorrelationQualityIssueBuilder correlationQualityIssueBuilder;
    private final VexQualityIssueBuilder vexQualityIssueBuilder;
    private final LifecycleQualityIssueBuilder lifecycleQualityIssueBuilder;
    private final ProjectionFreshnessIssueBuilder projectionFreshnessIssueBuilder;
    private final QualityIssuePersistenceService qualityIssuePersistenceService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public QualityIssueRefreshService(
            TenantRepository tenantRepository,
            NamedParameterJdbcTemplate jdbcTemplate,
            IngestionQualityIssueBuilder ingestionQualityIssueBuilder,
            NormalizationQualityIssueBuilder normalizationQualityIssueBuilder,
            CorrelationQualityIssueBuilder correlationQualityIssueBuilder,
            VexQualityIssueBuilder vexQualityIssueBuilder,
            LifecycleQualityIssueBuilder lifecycleQualityIssueBuilder,
            ProjectionFreshnessIssueBuilder projectionFreshnessIssueBuilder,
            QualityIssuePersistenceService qualityIssuePersistenceService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.tenantRepository = tenantRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.ingestionQualityIssueBuilder = ingestionQualityIssueBuilder;
        this.normalizationQualityIssueBuilder = normalizationQualityIssueBuilder;
        this.correlationQualityIssueBuilder = correlationQualityIssueBuilder;
        this.vexQualityIssueBuilder = vexQualityIssueBuilder;
        this.lifecycleQualityIssueBuilder = lifecycleQualityIssueBuilder;
        this.projectionFreshnessIssueBuilder = projectionFreshnessIssueBuilder;
        this.qualityIssuePersistenceService = qualityIssuePersistenceService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional
    public int refreshAll() {
        int total = 0;
        for (Tenant tenant : tenantRepository.findAllByOrderByCreatedAtAsc()) {
            total += refreshTenant(tenant);
        }
        return total;
    }

    @Transactional
    public int refreshTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return 0;
        }
        return tenantSchemaExecutionService.run(tenant, () -> {
            UUID tenantId = tenant.getId();
            List<QualityIssueRecord> issues = buildIssuesForTenant(tenantId);
            qualityIssuePersistenceService.upsertRows(issues);
            qualityIssuePersistenceService.deleteStaleRows(tenantId, issues);
            return issues.size();
        });
    }

    public void ensureTenantProjection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return;
        }
        tenantSchemaExecutionService.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource().addValue("tenantId", tenant.getId());
            Long projectedCount = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM quality_issue_projection",
                    params,
                    Long.class
            );
            if (projectedCount != null && projectedCount > 0L) {
                return;
            }
            Long sourceCount = jdbcTemplate.queryForObject("""
                    SELECT
                      COALESCE((SELECT COUNT(*) FROM inventory_components), 0)
                      + COALESCE((SELECT COUNT(*) FROM vulnerabilities), 0)
                      + COALESCE((SELECT COUNT(*) FROM sync_runs), 0)
                    """, params, Long.class);
            if (sourceCount != null && sourceCount > 0L) {
                refreshTenant(tenant);
            }
        });
    }

    private List<QualityIssueRecord> buildIssuesForTenant(UUID tenantId) {
        LinkedHashMap<String, QualityIssueRecord> issues = new LinkedHashMap<>();

        Set<UUID> missingIdentityComponentIds = new LinkedHashSet<>();
        Set<UUID> noCandidateComponentIds = new LinkedHashSet<>();
        Set<UUID> fallbackOnlyComponentIds = new LinkedHashSet<>();
        Set<UUID> failedSources = new LinkedHashSet<>();
        Set<UUID> vendorOnlyVulnerabilityIds = new LinkedHashSet<>();
        Set<String> conflictedVexPairs = new LinkedHashSet<>();
        Set<UUID> needsEolMappingIdentityIds = new LinkedHashSet<>();

        addIssueRecords(issues, ingestionQualityIssueBuilder.buildSourceRunFailedIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, ingestionQualityIssueBuilder.buildSourceRunPartialFailureIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, ingestionQualityIssueBuilder.buildSourceFeedStaleIssues(tenantId, failedSources), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, ingestionQualityIssueBuilder.buildIngestedNoDownstreamRecordsIssues(tenantId), failedSources, missingIdentityComponentIds);

        List<QualityIssueRecord> missingIdentityIssues = normalizationQualityIssueBuilder.buildComponentMissingSoftwareIdentityIssues(tenantId);
        addIssueRecords(issues, missingIdentityIssues, failedSources, missingIdentityComponentIds);

        addIssueRecords(issues, normalizationQualityIssueBuilder.buildComponentMissingNormalizedNameIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, normalizationQualityIssueBuilder.buildComponentMissingVersionIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, normalizationQualityIssueBuilder.buildHostLowConfidenceAliasIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, normalizationQualityIssueBuilder.buildHostDiscoveryModelReviewIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, normalizationQualityIssueBuilder.buildVulnerabilityTargetIdentityUnresolvedIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, normalizationQualityIssueBuilder.buildVexProductKeyUnresolvedIssues(tenantId), failedSources, missingIdentityComponentIds);

        List<QualityIssueRecord> noCandidateIssues = correlationQualityIssueBuilder
                .buildComponentNoCorrelationCandidatesIssues(tenantId, missingIdentityComponentIds);
        addIssueRecords(issues, noCandidateIssues, failedSources, missingIdentityComponentIds);
        noCandidateIssues.stream()
                .map(QualityIssueRecord::componentId)
                .filter(Objects::nonNull)
                .forEach(noCandidateComponentIds::add);

        List<QualityIssueRecord> fallbackOnlyIssues = correlationQualityIssueBuilder.buildComponentFallbackOnlyCorrelationIssues(
                tenantId,
                missingIdentityComponentIds,
                noCandidateComponentIds
        );
        addIssueRecords(issues, fallbackOnlyIssues, failedSources, missingIdentityComponentIds);
        fallbackOnlyIssues.stream()
                .map(QualityIssueRecord::componentId)
                .filter(Objects::nonNull)
                .forEach(fallbackOnlyComponentIds::add);

        addIssueRecords(
                issues,
                correlationQualityIssueBuilder.buildComponentLowConfidenceMatchIssues(
                        tenantId,
                        missingIdentityComponentIds,
                        noCandidateComponentIds,
                        fallbackOnlyComponentIds
                ),
                failedSources,
                missingIdentityComponentIds
        );

        List<QualityIssueRecord> vendorOnlyIssues = vexQualityIssueBuilder.buildVendorOnlyVexCoverageIssues(tenantId);
        addIssueRecords(issues, vendorOnlyIssues, failedSources, missingIdentityComponentIds);
        vendorOnlyIssues.stream()
                .map(QualityIssueRecord::vulnerabilityId)
                .filter(Objects::nonNull)
                .forEach(vendorOnlyVulnerabilityIds::add);

        List<QualityIssueRecord> vexConflictIssues = vexQualityIssueBuilder.buildOpenFindingConflictsWithVexIssues(tenantId);
        addIssueRecords(issues, vexConflictIssues, failedSources, missingIdentityComponentIds);
        vexConflictIssues.stream()
                .map(record -> record.componentId() == null || record.vulnerabilityId() == null
                        ? null
                        : record.componentId() + ":" + record.vulnerabilityId())
                .filter(Objects::nonNull)
                .forEach(conflictedVexPairs::add);

        addIssueRecords(
                issues,
                vexQualityIssueBuilder.buildAwaitingExactVexIssues(tenantId, vendorOnlyVulnerabilityIds, conflictedVexPairs),
                failedSources,
                missingIdentityComponentIds
        );
        addIssueRecords(issues, vexQualityIssueBuilder.buildStaleVexMatchIssues(tenantId), failedSources, missingIdentityComponentIds);

        List<QualityIssueRecord> eolMappingIssues = lifecycleQualityIssueBuilder.buildSoftwareIdentityNeedsEolMappingIssues(tenantId);
        addIssueRecords(issues, eolMappingIssues, failedSources, missingIdentityComponentIds);
        eolMappingIssues.stream()
                .map(QualityIssueRecord::softwareIdentityId)
                .filter(Objects::nonNull)
                .forEach(needsEolMappingIdentityIds::add);

        addIssueRecords(
                issues,
                lifecycleQualityIssueBuilder.buildSoftwareIdentityUnknownLifecycleIssues(tenantId, needsEolMappingIdentityIds),
                failedSources,
                missingIdentityComponentIds
        );
        addIssueRecords(
                issues,
                lifecycleQualityIssueBuilder.buildSoftwareIdentityCycleUnresolvedIssues(tenantId, needsEolMappingIdentityIds),
                failedSources,
                missingIdentityComponentIds
        );

        addIssueRecords(issues, projectionFreshnessIssueBuilder.buildSummaryProjectionStaleIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, projectionFreshnessIssueBuilder.buildCrossViewCountMismatchIssues(tenantId), failedSources, missingIdentityComponentIds);
        addIssueRecords(issues, projectionFreshnessIssueBuilder.buildPostRecomputeProjectionPendingIssues(tenantId), failedSources, missingIdentityComponentIds);

        return new ArrayList<>(issues.values());
    }

    private void addIssueRecords(
            Map<String, QualityIssueRecord> issues,
            List<QualityIssueRecord> candidates,
            Set<UUID> ignoredSources,
            Set<UUID> ignoredComponents
    ) {
        if (candidates == null || candidates.isEmpty()) {
            return;
        }
        for (QualityIssueRecord issue : candidates) {
            if (issue == null || issue.issueKey() == null || issue.issueKey().isBlank()) {
                continue;
            }
            issues.putIfAbsent(issue.issueKey(), issue);
        }
    }
}
