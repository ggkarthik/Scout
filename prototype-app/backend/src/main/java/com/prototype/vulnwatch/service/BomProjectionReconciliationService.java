package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.Map;
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
    private final BomComponentRepository bomComponentRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final AssetRepository assetRepository;
    private final AtomicInteger lastDriftCount = new AtomicInteger();

    public BomProjectionReconciliationService(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            BomIngestionRecordRepository bomIngestionRecordRepository,
            BomComponentRepository bomComponentRepository,
            InventoryComponentRepository inventoryComponentRepository,
            AssetRepository assetRepository,
            ObjectProvider<MeterRegistry> meterRegistryProvider
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.bomIngestionRecordRepository = bomIngestionRecordRepository;
        this.bomComponentRepository = bomComponentRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.assetRepository = assetRepository;
        MeterRegistry meterRegistry = meterRegistryProvider.getIfAvailable();
        if (meterRegistry != null) {
            Gauge.builder("bom.projection.drift.count", lastDriftCount, AtomicInteger::doubleValue)
                    .description("Number of tenant assets whose BOM component projection diverges from inventory components")
                    .register(meterRegistry);
        }
    }

    @Scheduled(fixedDelayString = "${app.bom.reconciliation.interval-ms:300000}")
    public void reconcileProjectionDrift() {
        int driftCount = 0;
        for (Tenant tenant : tenantService.listActiveTenants()) {
            try {
                driftCount += tenantSchemaExecutionService.run(tenant, reconcileTenant(tenant));
            } catch (Exception ex) {
                LOG.warn("Failed BOM projection reconciliation for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
            }
        }
        lastDriftCount.set(driftCount);
    }

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
                List<BomIngestionRecord> assetBoms = bomsByAsset.getOrDefault(asset.getId(), List.of());
                long canonicalCount = bomComponentRepository.findByBomIdInAndActiveTrue(
                                assetBoms.stream().map(BomIngestionRecord::getId).toList())
                        .size();
                long projectedCount = inventoryComponentRepository.findByAssetAndComponentStatus(asset, InventoryComponentStatus.ACTIVE).size();
                if (canonicalCount != projectedCount) {
                    driftedAssets++;
                    LOG.warn(
                            "BOM projection drift detected for tenant {} asset {} (canonical={}, projected={})",
                            tenant.getId(),
                            asset.getIdentifier(),
                            canonicalCount,
                            projectedCount
                    );
                }
            }
            return driftedAssets;
        };
    }
}
