package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BomComponentContribution;
import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class BomProjectionReconciliationService {

    private static final Logger LOG = LoggerFactory.getLogger(BomProjectionReconciliationService.class);

    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final BomIngestionRecordRepository bomIngestionRecordRepository;
    private final BomSourceRepository bomSourceRepository;
    private final BomComponentContributionRepository bomComponentContributionRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final AssetRepository assetRepository;
    private final AtomicInteger lastDriftCount = new AtomicInteger();
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public BomProjectionReconciliationService(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            BomIngestionRecordRepository bomIngestionRecordRepository,
            BomSourceRepository bomSourceRepository,
            BomComponentContributionRepository bomComponentContributionRepository,
            InventoryComponentRepository inventoryComponentRepository,
            AssetRepository assetRepository,
            ObjectProvider<MeterRegistry> meterRegistryProvider
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.bomIngestionRecordRepository = bomIngestionRecordRepository;
        this.bomSourceRepository = bomSourceRepository;
        this.bomComponentContributionRepository = bomComponentContributionRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.assetRepository = assetRepository;
        MeterRegistry meterRegistry = meterRegistryProvider.getIfAvailable();
        if (meterRegistry != null) {
            Gauge.builder("bom.projection.drift.count", lastDriftCount, AtomicInteger::doubleValue)
                    .description("Number of tenant assets whose BOM component projection diverges from inventory components")
                    .register(meterRegistry);
        }
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @Scheduled(fixedDelayString = "${app.bom.reconciliation.interval-ms:300000}")
    public void reconcileProjectionDrift() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("bom-projection.reconcile-drift")) {
            return;
        }
        int driftCount = TenantContext.runAsPlatform(() -> {
            int totalDriftCount = 0;
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    totalDriftCount += tenantSchemaExecutionService.run(tenant, reconcileTenant(tenant));
                } catch (Exception ex) {
                    LOG.warn("Failed BOM projection reconciliation for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return totalDriftCount;
        });
        lastDriftCount.set(driftCount);
    }

    /**
     * Drift is a component the BOM sources currently vouch for that is no longer active in
     * inventory: evidence says it is there and the projection disagrees.
     *
     * <p>It used to compare the raw BOM component count against the inventory component
     * count, which cannot hold now that an asset may carry several independent sources --
     * their components overlap, so summing them double-counts. It never really held: BOM
     * components include models, datasets and cryptographic assets that were never meant to
     * become inventory components, and several BOM components can resolve to one inventory
     * component, so the two numbers legitimately differed and the gauge reported healthy
     * assets as drifted.
     *
     * <p>Comparing distinct mapped components instead is only possible now that contributions
     * record which inventory component each source actually resolved to.
     */
    private Supplier<Integer> reconcileTenant(Tenant tenant) {
        return () -> {
            List<BomIngestionRecord> activeBoms = bomIngestionRecordRepository.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE)
                    .stream()
                    .filter(record -> record.getAssetId() != null)
                    .toList();
            if (activeBoms.isEmpty()) {
                return 0;
            }
            Map<UUID, List<BomIngestionRecord>> bomsByAsset = activeBoms.stream()
                    .collect(Collectors.groupingBy(BomIngestionRecord::getAssetId));
            List<Asset> assets = assetRepository.findAllById(bomsByAsset.keySet());
            int driftedAssets = 0;
            for (Asset asset : assets) {
                Set<UUID> supported = supportedComponentIds(asset.getId());
                if (supported.isEmpty()) {
                    // No claims recorded yet, so there is nothing to compare. An asset awaiting
                    // backfill is not drifted; reporting it as such would make the gauge useless
                    // for the whole migration window.
                    continue;
                }
                long stillActive = inventoryComponentRepository
                        .countByIdInAndComponentStatus(supported, InventoryComponentStatus.ACTIVE);
                if (stillActive != supported.size()) {
                    driftedAssets++;
                    LOG.warn(
                            "BOM projection drift detected for tenant {} asset {}: {} of {} supported components are no longer active",
                            tenant.getId(),
                            asset.getIdentifier(),
                            stillActive,
                            supported.size()
                    );
                }
            }
            return driftedAssets;
        };
    }

    /** Distinct inventory components this asset's sources currently vouch for. */
    private Set<UUID> supportedComponentIds(UUID assetId) {
        Set<UUID> supported = new LinkedHashSet<>();
        for (BomSource source : bomSourceRepository.findByAssetId(assetId)) {
            for (BomComponentContribution contribution : bomComponentContributionRepository
                    .findBySourceIdAndContributionState(source.getId(), BomContributionState.SUPPORTED)) {
                if (contribution.getInventoryComponentId() != null) {
                    supported.add(contribution.getInventoryComponentId());
                }
            }
        }
        return supported;
    }
}
