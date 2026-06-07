package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.SoftwareInventoryItem;
import com.prototype.vulnwatch.dto.AssetCriterionDto;
import com.prototype.vulnwatch.dto.InventoryAssetItemDto;
import com.prototype.vulnwatch.dto.InventoryResolutionResponse;
import com.prototype.vulnwatch.dto.ResolvedInventorySoftwareDto;
import com.prototype.vulnwatch.repo.SoftwareInventoryItemRepository;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class InventoryResolutionService {

    private final SoftwareInventoryItemRepository repository;

    public InventoryResolutionService(SoftwareInventoryItemRepository repository) {
        this.repository = repository;
    }

    public InventoryResolutionResponse resolveInventory(List<AssetCriterionDto> criteria) {
        if (criteria == null || criteria.isEmpty()) {
            return new InventoryResolutionResponse(Collections.emptyList(), 0);
        }
        UUID tenantId = TenantContext.getCurrentTenantId();

        Map<String, List<InventoryAssetItemDto>> assetsByKey = new LinkedHashMap<>();
        Map<String, SoftwareInventoryItem> representativeByKey = new LinkedHashMap<>();

        for (AssetCriterionDto criterion : criteria) {
            String softwareTerm = criterion.software() != null ? criterion.software().trim() : "";
            if (softwareTerm.isEmpty()) continue;
            String versionTerm = criterion.version() != null ? criterion.version().trim() : "";

            List<SoftwareInventoryItem> items =
                    repository.searchActiveByPackageNameContaining(tenantId, softwareTerm);

            for (SoftwareInventoryItem item : items) {
                if (!fieldMatches(item.getVersion(), versionTerm)) continue;

                InventoryComponent ic = item.getComponent();
                String software = item.getPackageName();
                String version = item.getVersion() != null ? item.getVersion() : "-";
                String key = normalize(software) + "::" + normalize(version);

                representativeByKey.putIfAbsent(key, item);
                List<InventoryAssetItemDto> assetList = assetsByKey.computeIfAbsent(key, k -> new ArrayList<>());

                Asset asset = item.getAsset();
                if (asset != null) {
                    String componentId = ic.getId().toString();
                    boolean alreadyPresent = assetList.stream()
                            .anyMatch(a -> componentId.equals(a.componentId()));
                    if (!alreadyPresent) {
                        assetList.add(new InventoryAssetItemDto(
                                componentId,
                                asset.getId().toString(),
                                asset.getName(),
                                asset.getIdentifier(),
                                asset.getType() != null ? asset.getType().name() : null,
                                item.getPackageName(),
                                item.getVersion(),
                                item.getEcosystem(),
                                ic.getIsEol(),
                                ic.getEolDate() != null ? ic.getEolDate().toString() : null,
                                ic.getEolSupportEndDate() != null ? ic.getEolSupportEndDate().toString() : null
                        ));
                    }
                }
            }
        }

        List<ResolvedInventorySoftwareDto> resolved = new ArrayList<>();
        for (Map.Entry<String, SoftwareInventoryItem> entry : representativeByKey.entrySet()) {
            String key = entry.getKey();
            SoftwareInventoryItem rep = entry.getValue();
            InventoryComponent ic = rep.getComponent();

            String vendor = rep.getEcosystem() != null ? rep.getEcosystem() : "Inventory";
            String lifecycle = deriveLifecycle(ic);
            String endOfSupport = ic.getEolSupportEndDate() != null ? ic.getEolSupportEndDate().toString() : "—";
            String endOfLife = ic.getEolDate() != null ? ic.getEolDate().toString() : "—";
            String recommendedUpgrade = ic.getEolCycle() != null
                    ? "Upgrade to " + ic.getEolCycle()
                    : "Upgrade to the latest supported release";

            resolved.add(new ResolvedInventorySoftwareDto(
                    key,
                    rep.getPackageName(),
                    vendor,
                    rep.getVersion() != null ? rep.getVersion() : "-",
                    assetsByKey.getOrDefault(key, Collections.emptyList()),
                    lifecycle,
                    endOfSupport,
                    endOfLife,
                    recommendedUpgrade
            ));
        }

        int totalAssets = resolved.stream().mapToInt(r -> r.assets().size()).sum();
        return new InventoryResolutionResponse(resolved, totalAssets);
    }

    static boolean fieldMatches(String actual, String expected) {
        if (expected == null || expected.isBlank()) return true;
        if (actual == null || actual.isBlank()) return false;
        String a = actual.trim().toLowerCase(Locale.ROOT);
        String e = expected.trim().toLowerCase(Locale.ROOT);
        return a.equals(e) || a.contains(e);
    }

    static String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }

    static String deriveLifecycle(InventoryComponent ic) {
        if (Boolean.TRUE.equals(ic.getIsEol())) return "End of Life";
        String phase = ic.getSupportPhase();
        if (phase != null && !phase.isBlank()) {
            String lower = phase.toLowerCase(Locale.ROOT).replace('_', ' ');
            return Character.toUpperCase(lower.charAt(0)) + lower.substring(1);
        }
        if (ic.getEolDate() != null) {
            long days = ChronoUnit.DAYS.between(LocalDate.now(), ic.getEolDate());
            if (days >= 0 && days <= 90) return "Near End of Life";
        }
        return "Supported";
    }
}
