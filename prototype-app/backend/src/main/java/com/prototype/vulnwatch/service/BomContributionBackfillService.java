package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomAssetBackfillState;
import com.prototype.vulnwatch.domain.BomBackfillState;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.repo.BomAssetBackfillStateRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.PageRequest;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Reconstructs the source and contribution rows for BOM documents ingested before either
 * existed.
 *
 * <p>There is nothing to migrate: the BOM-to-inventory match was recomputed at ingest and
 * discarded, so the mapping has to be rebuilt from what survived. Two things did. Documents
 * were chained by {@code previous_bom_id}/{@code superseded_by}, and one chain is exactly one
 * logical source. And {@code inventory_components.sbom_upload_id} credits a component to the
 * upload that produced it.
 *
 * <p>That second link is single-valued, and re-ingesting an asset from another source
 * overwrites it. So a component can only be attributed to whichever source wrote it last, and
 * components an earlier source contributed are no longer attributable at all. Those are left
 * with no contribution rows on purpose. {@code deriveEvidenceState} maps an empty claim set to
 * LEGACY_UNKNOWN whatever the asset's backfill state, so marking an asset backfilled can never
 * turn a component we failed to attribute into one believed absent. Guessing would.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BomContributionBackfillService {

    private final BomIngestionRecordRepository recordRepository;
    private final BomSourceRepository sourceRepository;
    private final BomComponentContributionRepository contributionRepository;
    private final BomAssetBackfillStateRepository backfillStateRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final BomContributionService contributionService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TransactionTemplate transactionTemplate;

    @Value("${app.bom.contribution-backfill.batch-size:25}")
    private int batchSize = 25;

    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy =
            BackgroundTaskExecutionPolicy.allowAll();

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy policy) {
        this.backgroundTaskExecutionPolicy =
                policy == null ? BackgroundTaskExecutionPolicy.allowAll() : policy;
    }

    /**
     * Walks tenants backfilling assets whose documents predate source tracking.
     *
     * <p>Tenant context is established before each transaction opens, not inside it.
     * TenantAwareDataSource pins a connection's search_path when the connection is acquired,
     * and a transaction binds its connection at the start, so opening the transaction first
     * would silently run every tenant's backfill against the default schema.
     */
    @Scheduled(
            fixedDelayString = "${app.bom.contribution-backfill.interval-ms:300000}",
            initialDelayString = "${app.bom.contribution-backfill.initial-delay-ms:60000}")
    public void backfillPendingAssets() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("bom-contribution.backfill")) {
            return;
        }
        TenantContext.runAsPlatform(() -> {
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    tenantSchemaExecutionService.run(tenant, () -> {
                        List<UUID> assetIds = recordRepository.findAssetIdsAwaitingSourceBackfill(
                                PageRequest.of(0, Math.max(1, batchSize)));
                        for (UUID assetId : assetIds) {
                            try {
                                transactionTemplate.execute(status ->
                                        backfillAsset(tenant.getId(), assetId));
                            } catch (RuntimeException ex) {
                                // Recorded as FAILED against the asset; the sweep continues so
                                // one bad asset cannot stall the rest of the tenant.
                                log.warn("Contribution backfill skipped asset {} for tenant {}: {}",
                                        assetId, tenant.getId(), ex.getMessage());
                            }
                        }
                        return null;
                    });
                } catch (Exception ex) {
                    log.warn("Contribution backfill failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return null;
        });
    }

    public record AssetBackfillResult(
            UUID assetId,
            int sourcesCreated,
            int recordsAssigned,
            int contributionsCreated,
            int componentsLeftUnattributed
    ) {
    }

    /**
     * Rebuilds one asset's sources and contributions, then opens the reconciliation gate for
     * it. Idempotent: document versions that already carry a source are skipped, so a re-run
     * neither duplicates sources nor disturbs live evidence.
     */
    public AssetBackfillResult backfillAsset(UUID tenantId, UUID assetId) {
        BomAssetBackfillState state = backfillStateRepository.findByAssetId(assetId)
                .orElseGet(() -> {
                    BomAssetBackfillState fresh = new BomAssetBackfillState();
                    fresh.setTenantId(tenantId);
                    fresh.setAssetId(assetId);
                    return fresh;
                });
        state.setAttemptCount(state.getAttemptCount() + 1);

        try {
            AssetBackfillResult result = reconstruct(tenantId, assetId);
            state.setState(BomBackfillState.BACKFILLED);
            state.setBackfilledAt(Instant.now());
            state.setFailureMessage(null);
            backfillStateRepository.save(state);
            return result;
        } catch (RuntimeException ex) {
            // Left un-backfilled deliberately: a partially reconstructed asset must not have
            // the gate opened, or absence could be concluded from claims that were never written.
            state.setState(BomBackfillState.FAILED);
            state.setBackfilledAt(null);
            state.setFailureMessage(ex.getMessage());
            backfillStateRepository.save(state);
            log.warn("Contribution backfill failed for asset {}", assetId, ex);
            throw ex;
        }
    }

    private AssetBackfillResult reconstruct(UUID tenantId, UUID assetId) {
        List<BomIngestionRecord> records = recordRepository.findByAssetId(assetId);
        if (records.isEmpty()) {
            return new AssetBackfillResult(assetId, 0, 0, 0, 0);
        }

        Map<UUID, BomIngestionRecord> byId = new LinkedHashMap<>();
        for (BomIngestionRecord record : records) {
            byId.put(record.getId(), record);
        }

        int sourcesCreated = 0;
        int recordsAssigned = 0;
        int contributionsCreated = 0;
        Set<UUID> attributed = new LinkedHashSet<>();
        Set<UUID> visited = new HashSet<>();

        for (BomIngestionRecord record : records) {
            if (visited.contains(record.getId())) {
                continue;
            }
            List<BomIngestionRecord> chain = chainFrom(record, byId, visited);
            if (chain.stream().allMatch(r -> r.getSourceId() != null)) {
                continue;
            }

            BomIngestionRecord current = currentOf(chain);
            BomSource source = new BomSource();
            source.setTenantId(tenantId);
            source.setBomType(current.getBomType());
            source.setAssetId(assetId);
            source.setSupplier(current.getSupplier());
            source.setSourceReference(current.getSourceReference());
            source.setCurrentBomId(current.getId());
            source.setRevision(chain.size());
            // Never inferred as complete. A historical document left no record of anyone
            // asserting it covered the asset, and only an audited assertion may do that.
            source.setCompleteness(BomSourceCompleteness.PARTIAL);
            source = sourceRepository.save(source);
            sourcesCreated++;

            for (BomIngestionRecord version : chain) {
                if (version.getSourceId() != null) {
                    continue;
                }
                version.setSourceId(source.getId());
                version.setCompleteness(BomSourceCompleteness.PARTIAL);
                recordRepository.save(version);
                recordsAssigned++;
            }

            contributionsCreated += rebuildContributions(tenantId, assetId, source, current, attributed);
        }

        int unattributed = countUnattributedComponents(assetId, attributed);
        if (unattributed > 0) {
            log.info("Backfill left {} of asset {}'s components unattributed; they stay LEGACY_UNKNOWN",
                    unattributed, assetId);
        }
        if (!attributed.isEmpty()) {
            contributionService.recomputeEvidenceStates(assetId, attributed, Instant.now());
        }
        return new AssetBackfillResult(
                assetId, sourcesCreated, recordsAssigned, contributionsCreated, unattributed);
    }

    private int rebuildContributions(
            UUID tenantId, UUID assetId, BomSource source, BomIngestionRecord current, Set<UUID> attributed) {
        if (current.getSbomUploadId() == null) {
            return 0;
        }
        List<InventoryComponent> components =
                inventoryComponentRepository.findByAsset_IdAndSbomUpload_Id(assetId, current.getSbomUploadId());
        Instant now = Instant.now();
        List<BomComponentContribution> toSave = new ArrayList<>();
        for (InventoryComponent component : components) {
            if (component.getId() == null
                    || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
                continue;
            }
            if (contributionRepository
                    .findBySourceIdAndInventoryComponentId(source.getId(), component.getId())
                    .isPresent()) {
                continue;
            }
            BomComponentContribution contribution = new BomComponentContribution();
            contribution.setTenantId(tenantId);
            contribution.setSourceId(source.getId());
            contribution.setBomId(current.getId());
            // Unknowable: the BOM component that justified this match was never recorded.
            contribution.setBomComponentId(null);
            contribution.setInventoryComponentId(component.getId());
            contribution.setResolvedIdentityKey(identityKey(component));
            contribution.setContributionState(BomContributionState.SUPPORTED);
            contribution.setAuthoritativeAbsence(false);
            contribution.setFirstContributedAt(now);
            contribution.setLastContributedAt(now);
            toSave.add(contribution);
            attributed.add(component.getId());
        }
        if (toSave.isEmpty()) {
            return 0;
        }
        contributionRepository.saveAll(toSave);
        return toSave.size();
    }

    /** Walks back to the chain's root, then forward, so each chain is visited once. */
    private List<BomIngestionRecord> chainFrom(
            BomIngestionRecord seed, Map<UUID, BomIngestionRecord> byId, Set<UUID> visited) {
        BomIngestionRecord root = seed;
        Set<UUID> backGuard = new HashSet<>();
        while (root.getPreviousBomId() != null
                && byId.containsKey(root.getPreviousBomId())
                && backGuard.add(root.getId())) {
            root = byId.get(root.getPreviousBomId());
        }

        List<BomIngestionRecord> chain = new ArrayList<>();
        BomIngestionRecord cursor = root;
        // The guard is defensive: a corrupted supersede link could otherwise loop forever.
        Set<UUID> forwardGuard = new HashSet<>();
        while (cursor != null && forwardGuard.add(cursor.getId())) {
            chain.add(cursor);
            visited.add(cursor.getId());
            cursor = cursor.getSupersededBy() == null ? null : byId.get(cursor.getSupersededBy());
        }
        return chain;
    }

    private static BomIngestionRecord currentOf(List<BomIngestionRecord> chain) {
        return chain.stream()
                .filter(r -> r.getStatus() == BomStatus.ACTIVE)
                .reduce((first, second) -> second)
                .orElseGet(() -> chain.get(chain.size() - 1));
    }

    private int countUnattributedComponents(UUID assetId, Set<UUID> attributed) {
        int unattributed = 0;
        List<InventoryComponent> all = inventoryComponentRepository.findByAssetId(assetId);
        for (InventoryComponent component : all) {
            if (component.getComponentStatus() == InventoryComponentStatus.ACTIVE
                    && component.getId() != null
                    && !attributed.contains(component.getId())) {
                unattributed++;
            }
        }
        return unattributed;
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
