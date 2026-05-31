package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.dto.AssetCriterionDto;
import com.prototype.vulnwatch.dto.FalsePositiveAnalysisResponse;
import com.prototype.vulnwatch.dto.FalsePositiveResultDto;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class FalsePositiveAnalysisService {

    private static final String NOT_AFFECTED = "NOT_AFFECTED";

    private final ComponentVulnerabilityStateRepository repository;

    public FalsePositiveAnalysisService(ComponentVulnerabilityStateRepository repository) {
        this.repository = repository;
    }

    public FalsePositiveAnalysisResponse analyzeFalsePositives(
            String cveExternalId, List<AssetCriterionDto> criteria) {

        UUID tenantId = TenantContext.getCurrentTenantId();

        List<ComponentVulnerabilityState> states =
                repository.findWithComponentsByTenantAndCve(tenantId, cveExternalId);

        Map<String, List<ComponentVulnerabilityState>> grouped = new LinkedHashMap<>();
        for (ComponentVulnerabilityState state : states) {
            InventoryComponent ic = state.getComponent();
            String version = ic.getVersion() != null ? ic.getVersion() : "-";
            String key = InventoryResolutionService.normalize(ic.getPackageName())
                    + "::" + InventoryResolutionService.normalize(version);
            grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(state);
        }

        List<FalsePositiveResultDto> results = new ArrayList<>();

        for (Map.Entry<String, List<ComponentVulnerabilityState>> entry : grouped.entrySet()) {
            List<ComponentVulnerabilityState> statesForSoftware = entry.getValue();
            InventoryComponent ic = statesForSoftware.get(0).getComponent();

            boolean falsePositive = statesForSoftware.stream()
                    .anyMatch(s -> NOT_AFFECTED.equalsIgnoreCase(s.getVexStatus()));

            long notImpactedCount = statesForSoftware.stream()
                    .filter(s -> NOT_AFFECTED.equalsIgnoreCase(s.getVexStatus()))
                    .count();

            String vexProvider = statesForSoftware.stream()
                    .filter(s -> s.getVexProvider() != null)
                    .map(ComponentVulnerabilityState::getVexProvider)
                    .findFirst().orElse(null);

            boolean hasVexData = statesForSoftware.stream()
                    .anyMatch(s -> s.getVexStatus() != null);

            String statusLabel, statusDetail, statusTone, vendorAdvisory, vendorGuidance;
            if (falsePositive) {
                statusLabel = "No";
                statusDetail = "VEX assertion indicates this component is not affected.";
                statusTone = "no";
                vendorAdvisory = vexProvider != null ? vexProvider + " advisory" : "Vendor advisory";
                vendorGuidance = "The vendor has assessed this component as not affected by this vulnerability.";
            } else if (hasVexData) {
                statusLabel = "Waiting vendor assessment";
                statusDetail = "VEX data present but does not confirm non-applicability.";
                statusTone = "waiting";
                vendorAdvisory = vexProvider != null ? vexProvider : "";
                vendorGuidance = "Installed software matched a vulnerability target. Analyst review required.";
            } else {
                statusLabel = "Waiting vendor assessment";
                statusDetail = "No VEX data available for this component.";
                statusTone = "waiting";
                vendorAdvisory = "";
                vendorGuidance = "Installed software matched a vulnerability target. No vendor assessment found.";
            }

            String version = ic.getVersion() != null ? ic.getVersion() : "-";
            results.add(new FalsePositiveResultDto(
                    entry.getKey(),
                    ic.getPackageName(),
                    version,
                    falsePositive,
                    (int) notImpactedCount,
                    vendorAdvisory,
                    vendorGuidance,
                    statusLabel,
                    statusDetail,
                    statusTone
            ));
        }

        // Fallback: criteria-driven empty rows when no DB correlation exists for this CVE
        if (results.isEmpty() && criteria != null) {
            for (AssetCriterionDto c : criteria) {
                if (c.software() == null || c.software().isBlank()) continue;
                String version = c.version() != null ? c.version() : "-";
                String key = InventoryResolutionService.normalize(c.software())
                        + "::" + InventoryResolutionService.normalize(version);
                results.add(new FalsePositiveResultDto(
                        key, c.software(), version,
                        false, 0, "",
                        "No inventory correlation data found for this CVE.",
                        "Waiting vendor assessment",
                        "No matched component found in vulnerability correlation data.",
                        "waiting"
                ));
            }
        }

        return new FalsePositiveAnalysisResponse(results);
    }
}
