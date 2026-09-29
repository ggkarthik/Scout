package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomAssetBackfillState;
import com.prototype.vulnwatch.domain.BomBackfillState;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.repo.BomAssetBackfillStateRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Records which sources vouch for which inventory components, and keeps each component's
 * aggregate evidence state in step.
 *
 * <p>The distinction this exists to preserve: a source ceasing to report a component is not
 * the component being gone. Another source may still report it, and the source that went
 * quiet may simply have been partial. Only a source that asserted it covers the asset's whole
 * software inventory can turn silence into a claim of absence.
 *
 * <p>This service never changes {@code component_status}, never refreshes observation
 * timestamps, and never touches findings. Withdrawing evidence is not remediation, and
 * retirement remains the existing policy-controlled path's decision.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BomContributionService {

    private final BomComponentContributionRepository contributionRepository;
    private final BomAssetBackfillStateRepository backfillStateRepository;
    private final InventoryComponentRepository inventoryComponentRepository;

    /**
     * Reconciles one document version's claims against the standing claims of its source.
     *
     * @param matchesByBomComponentId BOM component id to the inventory components it resolved to
     */
    public void syncContributions(
            BomIngestionRecord record,
            Map<UUID, List<InventoryComponent>> matchesByBomComponentId
    ) {
        if (record == null || record.getSourceId() == null) {
            // Rows predating source tracking carry no source; the backfill assigns one. Doing
            // nothing here is deliberate: with no source we cannot tell whose claim this is.
            return;
        }
        UUID sourceId = record.getSourceId();
        Instant now = Instant.now();
        boolean authoritative = record.getCompleteness() == BomSourceCompleteness.COMPLETE_ASSET_SOFTWARE;

        Map<UUID, UUID> bomComponentByInventoryId = new LinkedHashMap<>();
        Map<UUID, String> identityKeyByInventoryId = new LinkedHashMap<>();
        if (matchesByBomComponentId != null) {
            for (Map.Entry<UUID, List<InventoryComponent>> entry : matchesByBomComponentId.entrySet()) {
                if (entry.getValue() == null) {
                    continue;
                }
                for (InventoryComponent component : entry.getValue()) {
                    if (component == null || component.getId() == null) {
                        continue;
                    }
                    bomComponentByInventoryId.putIfAbsent(component.getId(), entry.getKey());
                    identityKeyByInventoryId.putIfAbsent(component.getId(), identityKey(component));
                }
            }
        }

        Set<UUID> supportedNow = bomComponentByInventoryId.keySet();
        List<BomComponentContribution> toSave = new ArrayList<>();

        for (UUID inventoryComponentId : supportedNow) {
            BomComponentContribution contribution = contributionRepository
                    .findBySourceIdAndInventoryComponentId(sourceId, inventoryComponentId)
                    .orElseGet(() -> {
                        BomComponentContribution fresh = new BomComponentContribution();
                        fresh.setTenantId(record.getTenant() == null ? null : record.getTenant().getId());
                        fresh.setSourceId(sourceId);
                        fresh.setInventoryComponentId(inventoryComponentId);
                        fresh.setFirstContributedAt(now);
                        return fresh;
                    });
            contribution.setBomId(record.getId());
            contribution.setBomComponentId(bomComponentByInventoryId.get(inventoryComponentId));
            contribution.setResolvedIdentityKey(identityKeyByInventoryId.get(inventoryComponentId));
            // A re-reported component is supported again, and any previous absence claim on
            // this source is retracted rather than left to linger as a conflict.
            contribution.setContributionState(BomContributionState.SUPPORTED);
            contribution.setWithdrawnAt(null);
            contribution.setAuthoritativeAbsence(false);
            contribution.setLastContributedAt(now);
            toSave.add(contribution);
        }

        // Claims this source used to make and no longer does. Withdrawn, not deleted: the
        // withdrawal and its timestamp are the audit trail.
        Set<UUID> withdrawn = new LinkedHashSet<>();
        for (BomComponentContribution standing : contributionRepository
                .findBySourceIdAndContributionState(sourceId, BomContributionState.SUPPORTED)) {
            if (supportedNow.contains(standing.getInventoryComponentId())) {
                continue;
            }
            standing.setContributionState(BomContributionState.WITHDRAWN);
            standing.setWithdrawnAt(now);
            // Only a complete claim converts silence into asserted absence. A partial document
            // withdraws its own support and says nothing about whether the component is there.
            standing.setAuthoritativeAbsence(authoritative);
            standing.setBomId(record.getId());
            toSave.add(standing);
            withdrawn.add(standing.getInventoryComponentId());
        }

        if (!toSave.isEmpty()) {
            contributionRepository.saveAll(toSave);
        }

        Set<UUID> affected = new LinkedHashSet<>(supportedNow);
        affected.addAll(withdrawn);
        recomputeEvidenceStates(record.getAssetId(), affected, now);
    }

    /**
     * Withdraws the claims a deleted document carried.
     *
     * <p>Deletion removes evidence; it does not assert that anything is absent. So the
     * withdrawal is recorded without authoritative absence, and a component left with no
     * remaining support becomes "presence unknown" rather than gone. Finding status is
     * untouched: deleting the document that reported a vulnerable component is not evidence
     * the vulnerability was fixed.
     */
    public void withdrawForDeletedDocument(BomIngestionRecord record) {
        if (record == null || record.getId() == null) {
            return;
        }
        Instant now = Instant.now();
        List<BomComponentContribution> toSave = new ArrayList<>();
        Set<UUID> affected = new LinkedHashSet<>();
        for (BomComponentContribution contribution : contributionRepository.findByBomId(record.getId())) {
            if (contribution.getContributionState() != BomContributionState.SUPPORTED) {
                continue;
            }
            contribution.setContributionState(BomContributionState.WITHDRAWN);
            contribution.setWithdrawnAt(now);
            contribution.setAuthoritativeAbsence(false);
            toSave.add(contribution);
            affected.add(contribution.getInventoryComponentId());
        }
        if (toSave.isEmpty()) {
            return;
        }
        contributionRepository.saveAll(toSave);
        recomputeEvidenceStates(record.getAssetId(), affected, now);
    }

    /** Re-derives the aggregate evidence state for components whose claims just changed. */
    public void recomputeEvidenceStates(UUID assetId, Set<UUID> inventoryComponentIds, Instant now) {
        if (inventoryComponentIds == null || inventoryComponentIds.isEmpty()) {
            return;
        }
        boolean assetBackfilled = isBackfilled(assetId);
        List<InventoryComponent> toSave = new ArrayList<>();
        for (UUID inventoryComponentId : inventoryComponentIds) {
            List<BomComponentContribution> contributions =
                    contributionRepository.findByInventoryComponentId(inventoryComponentId);
            BomEvidenceState state = deriveEvidenceState(contributions, assetBackfilled);
            inventoryComponentRepository.findById(inventoryComponentId).ifPresent(component -> {
                if (component.getBomEvidenceState() != state) {
                    component.setBomEvidenceState(state);
                    component.setBomEvidenceUpdatedAt(now);
                    toSave.add(component);
                }
            });
        }
        if (!toSave.isEmpty()) {
            inventoryComponentRepository.saveAll(toSave);
        }
    }

    /**
     * Support is always recognisable. Absence is not: concluding it requires the asset's
     * historical claims to have been reconstructed first, because before that a component with
     * no contribution rows is indistinguishable from one whose rows were never written.
     */
    static BomEvidenceState deriveEvidenceState(
            List<BomComponentContribution> contributions, boolean assetBackfilled) {
        if (contributions == null || contributions.isEmpty()) {
            return BomEvidenceState.LEGACY_UNKNOWN;
        }
        boolean anySupported = contributions.stream()
                .anyMatch(c -> c.getContributionState() == BomContributionState.SUPPORTED);
        boolean anyAssertedAbsence = contributions.stream()
                .anyMatch(c -> c.isAuthoritativeAbsence()
                        && c.getContributionState() == BomContributionState.WITHDRAWN);

        if (anySupported && anyAssertedAbsence) {
            // One source asserts the component is gone while another still reports it. Surface
            // the disagreement rather than letting either side win silently.
            return BomEvidenceState.CONFLICTING;
        }
        if (anySupported) {
            return BomEvidenceState.SUPPORTED;
        }
        return assetBackfilled ? BomEvidenceState.WITHDRAWN : BomEvidenceState.LEGACY_UNKNOWN;
    }

    private boolean isBackfilled(UUID assetId) {
        if (assetId == null) {
            return false;
        }
        return backfillStateRepository.findByAssetId(assetId)
                .map(BomAssetBackfillState::getState)
                .filter(state -> state == BomBackfillState.BACKFILLED)
                .isPresent();
    }

    private static String identityKey(InventoryComponent component) {
        String purl = normalise(component.getPurl());
        if (!purl.isEmpty()) {
            return purl;
        }
        return normalise(component.getEcosystem()) + "|"
                + normalise(component.getPackageName()) + "|"
                + normalise(component.getVersion());
    }

    private static String normalise(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
