package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomAssetBackfillState;
import com.prototype.vulnwatch.domain.BomBackfillState;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomAssetBackfillStateRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

/** Encodes the reconciliation rules: a source going quiet is not a component disappearing. */
class BomContributionServiceTest {

    private BomComponentContributionRepository contributionRepository;
    private BomAssetBackfillStateRepository backfillStateRepository;
    private InventoryComponentRepository inventoryComponentRepository;
    private BomContributionService service;

    private Tenant tenant;
    private UUID assetId;
    private UUID sourceId;

    @BeforeEach
    void setUp() {
        contributionRepository = mock(BomComponentContributionRepository.class);
        backfillStateRepository = mock(BomAssetBackfillStateRepository.class);
        inventoryComponentRepository = mock(InventoryComponentRepository.class);
        service = new BomContributionService(
                contributionRepository, backfillStateRepository, inventoryComponentRepository);
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        assetId = UUID.randomUUID();
        sourceId = UUID.randomUUID();
        when(contributionRepository.findBySourceIdAndInventoryComponentId(any(), any()))
                .thenReturn(Optional.empty());
        when(contributionRepository.findBySourceIdAndContributionState(any(), any()))
                .thenReturn(List.of());
        when(contributionRepository.findByInventoryComponentId(any())).thenReturn(List.of());
        when(inventoryComponentRepository.findById(any())).thenReturn(Optional.empty());
    }

    private BomIngestionRecord record(BomSourceCompleteness completeness) {
        BomIngestionRecord record = new BomIngestionRecord();
        record.setTenant(tenant);
        record.setAssetId(assetId);
        record.setSourceId(sourceId);
        record.setCompleteness(completeness);
        return record;
    }

    private InventoryComponent component(UUID id) {
        InventoryComponent component = new InventoryComponent();
        // id is @GeneratedValue and has no setter; tests need a stable one to key on.
        ReflectionTestUtils.setField(component, "id", id);
        component.setEcosystem("npm");
        component.setPackageName("lodash");
        component.setVersion("4.17.20");
        component.setPurl("pkg:npm/lodash@4.17.20");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return component;
    }

    private BomComponentContribution standing(UUID inventoryComponentId) {
        BomComponentContribution contribution = new BomComponentContribution();
        contribution.setId(UUID.randomUUID());
        contribution.setSourceId(sourceId);
        contribution.setInventoryComponentId(inventoryComponentId);
        contribution.setContributionState(BomContributionState.SUPPORTED);
        return contribution;
    }

    @Test
    void reportingAComponentRecordsSupportForThatSource() {
        UUID componentId = UUID.randomUUID();

        service.syncContributions(
                record(BomSourceCompleteness.PARTIAL),
                Map.of(UUID.randomUUID(), List.of(component(componentId))));

        ArgumentCaptor<List<BomComponentContribution>> saved = captureSaved();
        BomComponentContribution contribution = saved.getValue().get(0);
        assertEquals(BomContributionState.SUPPORTED, contribution.getContributionState());
        assertEquals("pkg:npm/lodash@4.17.20", contribution.getResolvedIdentityKey());
        assertNull(contribution.getWithdrawnAt());
        assertFalse(contribution.isAuthoritativeAbsence());
    }

    // Plan: "Partial replacement omits a component -> withdraw only that source's support".
    @Test
    void aPartialReplacementWithdrawsSupportWithoutAssertingAbsence() {
        UUID omitted = UUID.randomUUID();
        when(contributionRepository.findBySourceIdAndContributionState(
                sourceId, BomContributionState.SUPPORTED)).thenReturn(List.of(standing(omitted)));

        service.syncContributions(record(BomSourceCompleteness.PARTIAL), Map.of());

        BomComponentContribution withdrawn = captureSaved().getValue().get(0);
        assertEquals(BomContributionState.WITHDRAWN, withdrawn.getContributionState());
        assertNotNull(withdrawn.getWithdrawnAt(), "withdrawal must be timestamped for audit");
        assertFalse(withdrawn.isAuthoritativeAbsence(),
                "a partial document says nothing about whether the component is still there");
    }

    // Plan: "Complete software replacement omits a component -> record authoritative absence".
    @Test
    void aCompleteReplacementRecordsAuthoritativeAbsence() {
        UUID omitted = UUID.randomUUID();
        when(contributionRepository.findBySourceIdAndContributionState(
                sourceId, BomContributionState.SUPPORTED)).thenReturn(List.of(standing(omitted)));

        service.syncContributions(record(BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE), Map.of());

        BomComponentContribution withdrawn = captureSaved().getValue().get(0);
        assertEquals(BomContributionState.WITHDRAWN, withdrawn.getContributionState());
        assertTrue(withdrawn.isAuthoritativeAbsence());
    }

    @Test
    void reReportingAComponentRetractsAnEarlierAbsenceClaim() {
        UUID componentId = UUID.randomUUID();
        BomComponentContribution previouslyAbsent = standing(componentId);
        previouslyAbsent.setContributionState(BomContributionState.WITHDRAWN);
        previouslyAbsent.setAuthoritativeAbsence(true);
        previouslyAbsent.setWithdrawnAt(java.time.Instant.now());
        when(contributionRepository.findBySourceIdAndInventoryComponentId(sourceId, componentId))
                .thenReturn(Optional.of(previouslyAbsent));

        service.syncContributions(
                record(BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE),
                Map.of(UUID.randomUUID(), List.of(component(componentId))));

        assertEquals(BomContributionState.SUPPORTED, previouslyAbsent.getContributionState());
        assertNull(previouslyAbsent.getWithdrawnAt());
        assertFalse(previouslyAbsent.isAuthoritativeAbsence());
    }

    // A document with no source cannot be attributed, so it must not withdraw anyone's claims.
    @Test
    void aDocumentWithNoSourceChangesNothing() {
        BomIngestionRecord orphan = record(BomSourceCompleteness.PARTIAL);
        orphan.setSourceId(null);

        service.syncContributions(orphan, Map.of());

        verify(contributionRepository, never()).saveAll(any());
        verify(inventoryComponentRepository, never()).saveAll(any());
    }

    // Plan: "Document deletion -> mark evidence withdrawn; preserve finding status".
    // Deletion removes evidence; it is not a claim that anything is absent, so it must not
    // set authoritative absence or the component would look proven gone.
    @Test
    void deletingADocumentWithdrawsItsEvidenceWithoutAssertingAbsence() {
        BomIngestionRecord deleted = record(BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE);
        ReflectionTestUtils.setField(deleted, "id", UUID.randomUUID());
        BomComponentContribution carried = standing(UUID.randomUUID());
        when(contributionRepository.findByBomId(deleted.getId())).thenReturn(List.of(carried));

        service.withdrawForDeletedDocument(deleted);

        assertEquals(BomContributionState.WITHDRAWN, carried.getContributionState());
        assertNotNull(carried.getWithdrawnAt());
        assertFalse(carried.isAuthoritativeAbsence(),
                "deleting a document removes evidence; it does not prove the component is gone");
    }

    @Test
    void deletingADocumentThatCarriedNoClaimsChangesNothing() {
        BomIngestionRecord deleted = record(BomSourceCompleteness.PARTIAL);
        ReflectionTestUtils.setField(deleted, "id", UUID.randomUUID());
        when(contributionRepository.findByBomId(deleted.getId())).thenReturn(List.of());

        service.withdrawForDeletedDocument(deleted);

        verify(contributionRepository, never()).saveAll(any());
    }

    // Plan: "Current evidence still reports the component -> mark conflict; do not retire".
    @Test
    void assertedAbsenceAgainstLiveSupportIsAConflict() {
        BomComponentContribution supporting = standing(UUID.randomUUID());
        BomComponentContribution absent = standing(UUID.randomUUID());
        absent.setContributionState(BomContributionState.WITHDRAWN);
        absent.setAuthoritativeAbsence(true);

        assertEquals(BomEvidenceState.CONFLICTING,
                BomContributionService.deriveEvidenceState(List.of(supporting, absent), true));
    }

    @Test
    void liveSupportAloneIsSupported() {
        assertEquals(BomEvidenceState.SUPPORTED,
                BomContributionService.deriveEvidenceState(List.of(standing(UUID.randomUUID())), true));
    }

    // Plan: "No positive evidence remains -> show presence unknown; do not infer removal".
    // The backfill gate is what makes this safe: before an asset's historical claims are
    // reconstructed, "no contribution rows" and "rows were never written" look identical.
    @Test
    void absenceIsNotConcludedForAnAssetThatHasNotBeenBackfilled() {
        BomComponentContribution withdrawn = standing(UUID.randomUUID());
        withdrawn.setContributionState(BomContributionState.WITHDRAWN);

        assertEquals(BomEvidenceState.LEGACY_UNKNOWN,
                BomContributionService.deriveEvidenceState(List.of(withdrawn), false));
        assertEquals(BomEvidenceState.WITHDRAWN,
                BomContributionService.deriveEvidenceState(List.of(withdrawn), true));
    }

    @Test
    void aComponentWithNoClaimsAtAllStaysLegacyUnknown() {
        assertEquals(BomEvidenceState.LEGACY_UNKNOWN,
                BomContributionService.deriveEvidenceState(List.of(), true));
        assertEquals(BomEvidenceState.LEGACY_UNKNOWN,
                BomContributionService.deriveEvidenceState(null, true));
    }

    // Support is always recognisable even pre-backfill: the gate restrains concluding absence,
    // not recognising presence.
    @Test
    void supportIsRecognisedEvenBeforeBackfill() {
        assertEquals(BomEvidenceState.SUPPORTED,
                BomContributionService.deriveEvidenceState(List.of(standing(UUID.randomUUID())), false));
    }

    // The withdrawal guards, as a single assertion: evidence changes must not look like
    // remediation. Retirement stays with the existing policy-controlled path.
    @Test
    void recomputingEvidenceNeverRetiresAComponentOrRefreshesObservation() {
        UUID componentId = UUID.randomUUID();
        InventoryComponent existing = component(componentId);
        java.time.Instant observedBefore = existing.getLastObservedAt();
        BomComponentContribution withdrawn = standing(componentId);
        withdrawn.setContributionState(BomContributionState.WITHDRAWN);
        withdrawn.setAuthoritativeAbsence(true);

        when(contributionRepository.findByInventoryComponentId(componentId))
                .thenReturn(List.of(withdrawn));
        when(inventoryComponentRepository.findById(componentId)).thenReturn(Optional.of(existing));
        BomAssetBackfillState backfilled = new BomAssetBackfillState();
        backfilled.setState(BomBackfillState.BACKFILLED);
        when(backfillStateRepository.findByAssetId(assetId)).thenReturn(Optional.of(backfilled));

        service.recomputeEvidenceStates(assetId, java.util.Set.of(componentId), java.time.Instant.now());

        assertEquals(BomEvidenceState.WITHDRAWN, existing.getBomEvidenceState());
        assertEquals(InventoryComponentStatus.ACTIVE, existing.getComponentStatus(),
                "withdrawing evidence must not retire the component");
        assertNull(existing.getRetiredAt());
        assertEquals(observedBefore, existing.getLastObservedAt(),
                "withdrawal must not refresh the observation timestamp");
    }

    @SuppressWarnings("unchecked")
    private ArgumentCaptor<List<BomComponentContribution>> captureSaved() {
        ArgumentCaptor<List<BomComponentContribution>> captor = ArgumentCaptor.forClass(List.class);
        verify(contributionRepository).saveAll(captor.capture());
        return captor;
    }
}
