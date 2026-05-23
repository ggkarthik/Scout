package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

@ExtendWith(MockitoExtension.class)
class QualityIssueRefreshServiceTest {

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private NamedParameterJdbcTemplate jdbcTemplate;

    @Mock
    private IngestionQualityIssueBuilder ingestionQualityIssueBuilder;

    @Mock
    private NormalizationQualityIssueBuilder normalizationQualityIssueBuilder;

    @Mock
    private CorrelationQualityIssueBuilder correlationQualityIssueBuilder;

    @Mock
    private VexQualityIssueBuilder vexQualityIssueBuilder;

    @Mock
    private LifecycleQualityIssueBuilder lifecycleQualityIssueBuilder;

    @Mock
    private ProjectionFreshnessIssueBuilder projectionFreshnessIssueBuilder;

    @Mock
    private QualityIssuePersistenceService qualityIssuePersistenceService;

    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Test
    void refreshTenantBuildsAndPersistsUnionOfIssues() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(tenantSchemaExecutionService.run(eq(tenant), any(Supplier.class))).thenAnswer(invocation -> {
            @SuppressWarnings("unchecked")
            Supplier<Integer> supplier = invocation.getArgument(1);
            return supplier.get();
        });

        QualityIssueRecord ingestionIssue = issue(tenant.getId(), "ingestion:a");
        QualityIssueRecord normalizationIssue = issue(tenant.getId(), "normalization:b");

        when(ingestionQualityIssueBuilder.buildSourceRunFailedIssues(tenant.getId())).thenReturn(List.of(ingestionIssue));
        when(ingestionQualityIssueBuilder.buildSourceRunPartialFailureIssues(tenant.getId())).thenReturn(List.of());
        when(ingestionQualityIssueBuilder.buildSourceFeedStaleIssues(tenant.getId(), Set.of())).thenReturn(List.of());
        when(ingestionQualityIssueBuilder.buildIngestedNoDownstreamRecordsIssues(tenant.getId())).thenReturn(List.of());
        when(normalizationQualityIssueBuilder.buildComponentMissingSoftwareIdentityIssues(tenant.getId())).thenReturn(List.of(normalizationIssue));
        when(normalizationQualityIssueBuilder.buildComponentMissingNormalizedNameIssues(tenant.getId())).thenReturn(List.of());
        when(normalizationQualityIssueBuilder.buildComponentMissingVersionIssues(tenant.getId())).thenReturn(List.of());
        when(normalizationQualityIssueBuilder.buildHostLowConfidenceAliasIssues(tenant.getId())).thenReturn(List.of());
        when(normalizationQualityIssueBuilder.buildHostDiscoveryModelReviewIssues(tenant.getId())).thenReturn(List.of());
        when(normalizationQualityIssueBuilder.buildVulnerabilityTargetIdentityUnresolvedIssues(tenant.getId())).thenReturn(List.of());
        when(normalizationQualityIssueBuilder.buildVexProductKeyUnresolvedIssues(tenant.getId())).thenReturn(List.of());
        when(correlationQualityIssueBuilder.buildComponentNoCorrelationCandidatesIssues(tenant.getId(), Set.of())).thenReturn(List.of());
        when(correlationQualityIssueBuilder.buildComponentFallbackOnlyCorrelationIssues(tenant.getId(), Set.of(), Set.of())).thenReturn(List.of());
        when(correlationQualityIssueBuilder.buildComponentLowConfidenceMatchIssues(tenant.getId(), Set.of(), Set.of(), Set.of())).thenReturn(List.of());
        when(vexQualityIssueBuilder.buildVendorOnlyVexCoverageIssues(tenant.getId())).thenReturn(List.of());
        when(vexQualityIssueBuilder.buildOpenFindingConflictsWithVexIssues(tenant.getId())).thenReturn(List.of());
        when(vexQualityIssueBuilder.buildAwaitingExactVexIssues(tenant.getId(), Set.of(), Set.of())).thenReturn(List.of());
        when(vexQualityIssueBuilder.buildStaleVexMatchIssues(tenant.getId())).thenReturn(List.of());
        when(lifecycleQualityIssueBuilder.buildSoftwareIdentityNeedsEolMappingIssues(tenant.getId())).thenReturn(List.of());
        when(lifecycleQualityIssueBuilder.buildSoftwareIdentityUnknownLifecycleIssues(tenant.getId(), Set.of())).thenReturn(List.of());
        when(lifecycleQualityIssueBuilder.buildSoftwareIdentityCycleUnresolvedIssues(tenant.getId(), Set.of())).thenReturn(List.of());
        when(projectionFreshnessIssueBuilder.buildSummaryProjectionStaleIssues(tenant.getId())).thenReturn(List.of());
        when(projectionFreshnessIssueBuilder.buildCrossViewCountMismatchIssues(tenant.getId())).thenReturn(List.of());
        when(projectionFreshnessIssueBuilder.buildPostRecomputeProjectionPendingIssues(tenant.getId())).thenReturn(List.of());

        QualityIssueRefreshService service = createService();
        int count = service.refreshTenant(tenant);

        assertEquals(2, count);
        verify(qualityIssuePersistenceService).upsertRows(List.of(ingestionIssue, normalizationIssue));
        verify(qualityIssuePersistenceService).deleteStaleRows(tenant.getId(), List.of(ingestionIssue, normalizationIssue));
    }

    private QualityIssueRefreshService createService() {
        return new QualityIssueRefreshService(
                tenantRepository,
                jdbcTemplate,
                ingestionQualityIssueBuilder,
                normalizationQualityIssueBuilder,
                correlationQualityIssueBuilder,
                vexQualityIssueBuilder,
                lifecycleQualityIssueBuilder,
                projectionFreshnessIssueBuilder,
                qualityIssuePersistenceService,
                tenantSchemaExecutionService
        );
    }

    private QualityIssueRecord issue(UUID tenantId, String issueKey) {
        return new QualityIssueRecord(
                tenantId + ":" + issueKey,
                tenantId,
                issueKey,
                "INGESTION",
                "SOURCE_RUN_FAILED",
                "HIGH",
                "reason",
                "SYNC_RUN",
                "id",
                null,
                null,
                null,
                null,
                null,
                "Title",
                null,
                null,
                null,
                null,
                null,
                false,
                0,
                0,
                0,
                0,
                Instant.now(),
                Instant.now(),
                Instant.now(),
                "{}",
                "[]"
        );
    }
}
