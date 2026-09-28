package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomAssetBackfillState;
import com.prototype.vulnwatch.domain.BomBackfillState;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.repo.BomAssetBackfillStateRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

class BomContributionBackfillServiceTest {

    private BomIngestionRecordRepository recordRepository;
    private BomSourceRepository sourceRepository;
    private BomComponentContributionRepository contributionRepository;
    private BomAssetBackfillStateRepository backfillStateRepository;
    private InventoryComponentRepository inventoryComponentRepository;
    private BomContributionService contributionService;
    private com.prototype.vulnwatch.repo.BomComponentRepository bomComponentRepository;
    private com.prototype.vulnwatch.repo.FindingRepository findingRepository;
    private BomContributionBackfillService service;

    private UUID tenantId;
    private UUID assetId;

    @BeforeEach
    void setUp() {
        recordRepository = mock(BomIngestionRecordRepository.class);
        sourceRepository = mock(BomSourceRepository.class);
        contributionRepository = mock(BomComponentContributionRepository.class);
        backfillStateRepository = mock(BomAssetBackfillStateRepository.class);
        inventoryComponentRepository = mock(InventoryComponentRepository.class);
        contributionService = mock(BomContributionService.class);
        bomComponentRepository = mock(com.prototype.vulnwatch.repo.BomComponentRepository.class);
        findingRepository = mock(com.prototype.vulnwatch.repo.FindingRepository.class);
        // The scheduled sweep's collaborators are not exercised here: these tests drive
        // backfillAsset directly, which is the unit that does the reconstruction.
        // Argument order follows field declaration order, which is what
        // @RequiredArgsConstructor generates.
        service = new BomContributionBackfillService(
                recordRepository, sourceRepository, contributionRepository,
                backfillStateRepository, inventoryComponentRepository, contributionService,
                bomComponentRepository,
                new BomComponentCategorizationService(),
                findingRepository,
                mock(TenantService.class), mock(TenantSchemaExecutionService.class),
                mock(org.springframework.transaction.support.TransactionTemplate.class));
        tenantId = UUID.randomUUID();
        assetId = UUID.randomUUID();

        when(backfillStateRepository.findByAssetId(assetId)).thenReturn(Optional.empty());
        when(sourceRepository.save(any(BomSource.class))).thenAnswer(invocation -> {
            BomSource source = invocation.getArgument(0);
            if (source.getId() == null) {
                ReflectionTestUtils.setField(source, "id", UUID.randomUUID());
            }
            return source;
        });
        when(contributionRepository.findBySourceIdAndInventoryComponentId(any(), any()))
                .thenReturn(Optional.empty());
        when(inventoryComponentRepository.findByAssetId(assetId)).thenReturn(List.of());
        when(inventoryComponentRepository.findByAsset_IdAndSbomUpload_Id(any(), any()))
                .thenReturn(List.of());
    }

    private BomIngestionRecord version(UUID id, BomStatus status, UUID previous, UUID supersededBy, UUID uploadId) {
        BomIngestionRecord record = new BomIngestionRecord();
        ReflectionTestUtils.setField(record, "id", id);
        record.setAssetId(assetId);
        record.setBomType(BomType.SBOM);
        record.setStatus(status);
        record.setPreviousBomId(previous);
        record.setSupersededBy(supersededBy);
        record.setSbomUploadId(uploadId);
        record.setSupplier("acme");
        return record;
    }

    private InventoryComponent component(UUID id, InventoryComponentStatus status) {
        InventoryComponent component = new InventoryComponent();
        ReflectionTestUtils.setField(component, "id", id);
        component.setEcosystem("npm");
        component.setPackageName("lodash");
        component.setVersion("4.17.20");
        component.setPurl("pkg:npm/lodash@4.17.20");
        component.setComponentStatus(status);
        return component;
    }

    // previous_bom_id / superseded_by chains are the only surviving record of which documents
    // were versions of the same thing, so one chain must become exactly one source.
    @Test
    void aSupersedeChainBecomesOneSourceWhoseCurrentIsTheActiveVersion() {
        UUID older = UUID.randomUUID();
        UUID newer = UUID.randomUUID();
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(older, BomStatus.SUPERSEDED, null, newer, UUID.randomUUID()),
                version(newer, BomStatus.ACTIVE, older, null, UUID.randomUUID())));

        BomContributionBackfillService.AssetBackfillResult result =
                service.backfillAsset(tenantId, assetId);

        assertEquals(1, result.sourcesCreated());
        assertEquals(2, result.recordsAssigned(), "every version in the chain gets the source");

        ArgumentCaptor<BomSource> saved = ArgumentCaptor.forClass(BomSource.class);
        verify(sourceRepository).save(saved.capture());
        assertEquals(newer, saved.getValue().getCurrentBomId());
        assertEquals(2L, saved.getValue().getRevision());
    }

    @Test
    void unrelatedChainsBecomeSeparateSources() {
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, UUID.randomUUID()),
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, UUID.randomUUID())));

        assertEquals(2, service.backfillAsset(tenantId, assetId).sourcesCreated());
    }

    // A historical document left no record of anyone asserting it was complete, and only an
    // audited assertion may claim that. Inferring it would licence retiring components.
    @Test
    void backfilledSourcesAreNeverInferredComplete() {
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, UUID.randomUUID())));

        service.backfillAsset(tenantId, assetId);

        ArgumentCaptor<BomSource> saved = ArgumentCaptor.forClass(BomSource.class);
        verify(sourceRepository).save(saved.capture());
        assertEquals(BomSourceCompleteness.PARTIAL, saved.getValue().getCompleteness());
    }

    @Test
    void componentsCreditedToTheCurrentUploadBecomeSupportedClaims() {
        UUID uploadId = UUID.randomUUID();
        UUID componentId = UUID.randomUUID();
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, uploadId)));
        when(inventoryComponentRepository.findByAsset_IdAndSbomUpload_Id(assetId, uploadId))
                .thenReturn(List.of(component(componentId, InventoryComponentStatus.ACTIVE)));

        assertEquals(1, service.backfillAsset(tenantId, assetId).contributionsCreated());

        ArgumentCaptor<List<BomComponentContribution>> saved = captureContributions();
        BomComponentContribution contribution = saved.getValue().get(0);
        assertEquals(BomContributionState.SUPPORTED, contribution.getContributionState());
        assertEquals(componentId, contribution.getInventoryComponentId());
        assertFalse(contribution.isAuthoritativeAbsence());
        assertNull(contribution.getBomComponentId(),
                "the BOM component behind a historical match was never recorded");
    }

    // The central limitation. inventory_components.sbom_upload_id is single-valued and gets
    // overwritten on re-ingest, so components an earlier source contributed cannot be
    // attributed. They are reported and left claimless rather than guessed at -- an empty
    // claim set stays LEGACY_UNKNOWN regardless of the gate, so they can never look absent.
    @Test
    void componentsThatCannotBeAttributedAreReportedAndLeftWithoutClaims() {
        UUID uploadId = UUID.randomUUID();
        UUID attributable = UUID.randomUUID();
        UUID orphaned = UUID.randomUUID();
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, uploadId)));
        when(inventoryComponentRepository.findByAsset_IdAndSbomUpload_Id(assetId, uploadId))
                .thenReturn(List.of(component(attributable, InventoryComponentStatus.ACTIVE)));
        when(inventoryComponentRepository.findByAssetId(assetId)).thenReturn(List.of(
                component(attributable, InventoryComponentStatus.ACTIVE),
                component(orphaned, InventoryComponentStatus.ACTIVE)));

        BomContributionBackfillService.AssetBackfillResult result =
                service.backfillAsset(tenantId, assetId);

        assertEquals(1, result.contributionsCreated());
        assertEquals(1, result.componentsLeftUnattributed());
    }

    @Test
    void retiredComponentsAreNotGivenClaims() {
        UUID uploadId = UUID.randomUUID();
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, uploadId)));
        when(inventoryComponentRepository.findByAsset_IdAndSbomUpload_Id(assetId, uploadId))
                .thenReturn(List.of(component(UUID.randomUUID(), InventoryComponentStatus.RETIRED)));

        assertEquals(0, service.backfillAsset(tenantId, assetId).contributionsCreated());
        verify(contributionRepository, never()).saveAll(any());
    }

    @Test
    void versionsThatAlreadyCarryASourceAreLeftAlone() {
        BomIngestionRecord migrated = version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, UUID.randomUUID());
        migrated.setSourceId(UUID.randomUUID());
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(migrated));

        BomContributionBackfillService.AssetBackfillResult result =
                service.backfillAsset(tenantId, assetId);

        assertEquals(0, result.sourcesCreated(), "a re-run must not duplicate sources");
        verify(sourceRepository, never()).save(any());
    }

    @Test
    void successOpensTheReconciliationGateForTheAsset() {
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(
                version(UUID.randomUUID(), BomStatus.ACTIVE, null, null, UUID.randomUUID())));

        service.backfillAsset(tenantId, assetId);

        ArgumentCaptor<BomAssetBackfillState> saved = ArgumentCaptor.forClass(BomAssetBackfillState.class);
        verify(backfillStateRepository).save(saved.capture());
        assertEquals(BomBackfillState.BACKFILLED, saved.getValue().getState());
        assertNotNull(saved.getValue().getBackfilledAt());
    }

    // A half-reconstructed asset must not have the gate opened, or absence could be concluded
    // from claims that were never written.
    @Test
    void failurePreventsTheGateFromOpening() {
        when(recordRepository.findByAssetId(assetId)).thenThrow(new IllegalStateException("db gone"));

        assertThrows(IllegalStateException.class, () -> service.backfillAsset(tenantId, assetId));

        ArgumentCaptor<BomAssetBackfillState> saved = ArgumentCaptor.forClass(BomAssetBackfillState.class);
        verify(backfillStateRepository).save(saved.capture());
        assertEquals(BomBackfillState.FAILED, saved.getValue().getState());
        assertNull(saved.getValue().getBackfilledAt());
    }

    @SuppressWarnings("unchecked")
    private ArgumentCaptor<List<BomComponentContribution>> captureContributions() {
        ArgumentCaptor<List<BomComponentContribution>> captor = ArgumentCaptor.forClass(List.class);
        verify(contributionRepository).saveAll(captor.capture());
        return captor;
    }

    private com.prototype.vulnwatch.domain.BomComponent bomComponent(
            String name, String version, String componentType) {
        com.prototype.vulnwatch.domain.BomComponent component =
                new com.prototype.vulnwatch.domain.BomComponent();
        component.setName(name);
        component.setVersion(version);
        component.setComponentType(componentType);
        return component;
    }

    /**
     * Components ingested before the inventory path knew about component types. The type
     * survived on bom_components, so they can be identified and counted -- and they matter,
     * because each one is a model or dataset still being correlated for CVEs.
     */
    @Test
    void reportsInventoryComponentsWhoseOnlyBomEvidenceIsNonSoftware() {
        UUID bomId = UUID.randomUUID();
        BomIngestionRecord active = version(bomId, BomStatus.ACTIVE, null, null, UUID.randomUUID());
        when(recordRepository.findByAssetId(assetId)).thenReturn(List.of(active));
        when(bomComponentRepository.findByBomIdInAndActiveTrue(List.of(bomId))).thenReturn(List.of(
                bomComponent("llama-3", "3.1", "machine-learning-model"),
                bomComponent("transformers", "4.38.0", "library")));

        InventoryComponent model = component(UUID.randomUUID(), InventoryComponentStatus.ACTIVE);
        model.setPackageName("llama-3");
        model.setVersion("3.1");
        InventoryComponent library = component(UUID.randomUUID(), InventoryComponentStatus.ACTIVE);
        library.setPackageName("transformers");
        library.setVersion("4.38.0");
        when(inventoryComponentRepository.findByAssetId(assetId)).thenReturn(List.of(model, library));

        assertEquals(1, service.backfillAsset(tenantId, assetId).misclassifiedNonSoftwareComponents(),
                "only the model counts; the library belongs in software inventory");
    }

    /**
     * The "no independent software evidence" condition. A component an SBOM also reports as a
     * library is legitimately software, whatever an AI-BOM calls it, so it must not be
     * flagged for reclassification.
     */
    @Test
    void aComponentAlsoReportedAsSoftwareIsNotFlagged() {
        UUID bomId = UUID.randomUUID();
        when(recordRepository.findByAssetId(assetId))
                .thenReturn(List.of(version(bomId, BomStatus.ACTIVE, null, null, UUID.randomUUID())));
        when(bomComponentRepository.findByBomIdInAndActiveTrue(List.of(bomId))).thenReturn(List.of(
                bomComponent("torch", "2.1.0", "machine-learning-model"),
                bomComponent("torch", "2.1.0", "library")));

        InventoryComponent shared = component(UUID.randomUUID(), InventoryComponentStatus.ACTIVE);
        shared.setPackageName("torch");
        shared.setVersion("2.1.0");
        when(inventoryComponentRepository.findByAssetId(assetId)).thenReturn(List.of(shared));

        assertEquals(0, service.backfillAsset(tenantId, assetId).misclassifiedNonSoftwareComponents());
    }

    private void assetIsBackfilled() {
        BomAssetBackfillState state = new BomAssetBackfillState();
        state.setState(BomBackfillState.BACKFILLED);
        state.setBackfilledAt(java.time.Instant.now());
        when(backfillStateRepository.findByAssetId(assetId)).thenReturn(Optional.of(state));
    }

    private InventoryComponent misclassifiedModelOnAsset() {
        UUID bomId = UUID.randomUUID();
        when(recordRepository.findByAssetId(assetId))
                .thenReturn(List.of(version(bomId, BomStatus.ACTIVE, null, null, UUID.randomUUID())));
        when(bomComponentRepository.findByBomIdInAndActiveTrue(List.of(bomId)))
                .thenReturn(List.of(bomComponent("llama-3", "3.1", "machine-learning-model")));
        InventoryComponent model = component(UUID.randomUUID(), InventoryComponentStatus.ACTIVE);
        model.setPackageName("llama-3");
        model.setVersion("3.1");
        when(inventoryComponentRepository.findByAssetId(assetId)).thenReturn(List.of(model));
        return model;
    }

    // The default. Reporting is safe; retiring inventory and closing findings is not something
    // that should happen because a backfill ran.
    @Test
    void nothingIsRetiredUnlessTheCorrectionIsExplicitlyEnabled() {
        assetIsBackfilled();
        InventoryComponent model = misclassifiedModelOnAsset();

        service.backfillAsset(tenantId, assetId);

        assertEquals(InventoryComponentStatus.ACTIVE, model.getComponentStatus());
        verify(findingRepository, never()).saveAll(any());
    }

    @Test
    void whenEnabledAMisclassifiedComponentIsRetiredAndItsFindingClosedAsReclassified() {
        ReflectionTestUtils.setField(service, "retireNonSoftware", true);
        assetIsBackfilled();
        InventoryComponent model = misclassifiedModelOnAsset();

        com.prototype.vulnwatch.domain.Finding open = new com.prototype.vulnwatch.domain.Finding();
        open.setStatus(com.prototype.vulnwatch.domain.FindingStatus.OPEN);
        when(findingRepository.findByComponent_IdIn(List.of(model.getId()))).thenReturn(List.of(open));

        service.backfillAsset(tenantId, assetId);

        assertEquals(InventoryComponentStatus.RETIRED, model.getComponentStatus());
        assertNotNull(model.getRetiredAt());
        assertEquals(com.prototype.vulnwatch.domain.FindingStatus.AUTO_CLOSED, open.getStatus());
        assertEquals(com.prototype.vulnwatch.domain.FindingCloseReason.AUTO_RECLASSIFIED_NOT_SOFTWARE,
                open.getClosedReason(),
                "a classification correction must not be recorded as remediation or as removal");
        assertNotNull(open.getClosedAt());
    }

    // Before backfill, a component with no contribution rows is indistinguishable from one
    // whose rows were never written, so nothing may be concluded about it.
    @Test
    void anAssetThatIsNotBackfilledIsNeverCorrectedEvenWhenEnabled() {
        ReflectionTestUtils.setField(service, "retireNonSoftware", true);
        when(backfillStateRepository.findByAssetId(assetId)).thenReturn(Optional.empty());
        InventoryComponent model = misclassifiedModelOnAsset();

        service.backfillAsset(tenantId, assetId);

        assertEquals(InventoryComponentStatus.ACTIVE, model.getComponentStatus());
    }

    @Test
    void alreadyClosedFindingsAreLeftUntouched() {
        ReflectionTestUtils.setField(service, "retireNonSoftware", true);
        assetIsBackfilled();
        InventoryComponent model = misclassifiedModelOnAsset();

        com.prototype.vulnwatch.domain.Finding resolved = new com.prototype.vulnwatch.domain.Finding();
        resolved.setStatus(com.prototype.vulnwatch.domain.FindingStatus.RESOLVED);
        java.time.Instant closedBefore = java.time.Instant.parse("2024-01-01T00:00:00Z");
        resolved.setClosedAt(closedBefore);
        when(findingRepository.findByComponent_IdIn(List.of(model.getId()))).thenReturn(List.of(resolved));

        service.backfillAsset(tenantId, assetId);

        assertEquals(com.prototype.vulnwatch.domain.FindingStatus.RESOLVED, resolved.getStatus());
        assertEquals(closedBefore, resolved.getClosedAt(), "resolution history must survive");
    }
}
