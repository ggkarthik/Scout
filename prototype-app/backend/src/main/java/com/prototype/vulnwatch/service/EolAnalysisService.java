package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.SoftwareInventoryItem;
import com.prototype.vulnwatch.dto.AssetCriterionDto;
import com.prototype.vulnwatch.dto.EolAnalysisRequest;
import com.prototype.vulnwatch.dto.EolAnalysisResponse;
import com.prototype.vulnwatch.dto.EolAnalysisResultDto;
import com.prototype.vulnwatch.repo.SoftwareInventoryItemRepository;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class EolAnalysisService {

    private final SoftwareInventoryItemRepository repository;

    public EolAnalysisService(SoftwareInventoryItemRepository repository) {
        this.repository = repository;
    }

    public EolAnalysisResponse analyzeEol(List<AssetCriterionDto> criteria) {
        if (criteria == null || criteria.isEmpty()) {
            return new EolAnalysisResponse(Collections.emptyList());
        }
        UUID tenantId = TenantContext.getCurrentTenantId();

        Map<String, EolAnalysisResultDto> rows = new LinkedHashMap<>();

        for (AssetCriterionDto criterion : criteria) {
            String softwareTerm = criterion.software() != null ? criterion.software().trim() : "";
            if (softwareTerm.isEmpty()) continue;
            String versionTerm = criterion.version() != null ? criterion.version().trim() : "";

            List<SoftwareInventoryItem> items =
                    repository.searchActiveByPackageNameContaining(tenantId, softwareTerm);

            for (SoftwareInventoryItem item : items) {
                if (!InventoryResolutionService.fieldMatches(item.getVersion(), versionTerm)) continue;

                InventoryComponent ic = item.getComponent();
                String software = item.getPackageName();
                String version = item.getVersion() != null ? item.getVersion() : "-";
                String key = InventoryResolutionService.normalize(software)
                        + "::" + InventoryResolutionService.normalize(version);

                if (rows.containsKey(key)) continue;

                String vendor = item.getEcosystem() != null ? item.getEcosystem()
                        : (criterion.vendor() != null && !criterion.vendor().isBlank() ? criterion.vendor() : "Inventory");

                rows.put(key, new EolAnalysisResultDto(
                        key, software, vendor, version,
                        InventoryResolutionService.deriveLifecycle(ic),
                        ic.getEolSupportEndDate() != null ? ic.getEolSupportEndDate().toString() : "—",
                        ic.getEolDate() != null ? ic.getEolDate().toString() : "—",
                        ic.getEolCycle() != null ? "Upgrade to " + ic.getEolCycle() : "Upgrade to the latest supported release"
                ));
            }

            // Fallback row for criteria not covered by inventory
            String fallbackKey = InventoryResolutionService.normalize(softwareTerm)
                    + "::" + InventoryResolutionService.normalize(versionTerm.isEmpty() ? "-" : versionTerm);
            boolean alreadyCovered = rows.keySet().stream().anyMatch(existingKey -> {
                String existingSoftware = existingKey.split("::")[0];
                return InventoryResolutionService.fieldMatches(existingSoftware, softwareTerm)
                        || InventoryResolutionService.fieldMatches(softwareTerm, existingSoftware);
            });
            if (!alreadyCovered) {
                String vendor = criterion.vendor() != null && !criterion.vendor().isBlank()
                        ? criterion.vendor() : "—";
                String version = versionTerm.isEmpty() ? "—" : versionTerm;
                rows.put(fallbackKey, new EolAnalysisResultDto(
                        fallbackKey, softwareTerm, vendor, version,
                        "Unknown", "—", "—", "—"
                ));
            }
        }

        return new EolAnalysisResponse(new ArrayList<>(rows.values()));
    }
}
