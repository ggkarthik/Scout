package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.HostAliasResponse;
import com.prototype.vulnwatch.dto.HostAssetDetailResponse;
import com.prototype.vulnwatch.dto.HostAssetSummaryResponse;
import com.prototype.vulnwatch.dto.HostFindingResponse;
import com.prototype.vulnwatch.dto.HostSoftwareInstanceResponse;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.SoftwareInstanceRepository;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class HostInventoryReadService {

    private final CiRepository ciRepository;
    private final CiAliasRepository ciAliasRepository;
    private final SoftwareInstanceRepository softwareInstanceRepository;
    private final FindingRepository findingRepository;

    public HostInventoryReadService(
            CiRepository ciRepository,
            CiAliasRepository ciAliasRepository,
            SoftwareInstanceRepository softwareInstanceRepository,
            FindingRepository findingRepository
    ) {
        this.ciRepository = ciRepository;
        this.ciAliasRepository = ciAliasRepository;
        this.softwareInstanceRepository = softwareInstanceRepository;
        this.findingRepository = findingRepository;
    }

    @Transactional(readOnly = true)
    public HostAssetDetailResponse getHostDetail(Tenant tenant, UUID assetId, String sourceSystem) {
        if (tenant == null || tenant.getId() == null || assetId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Host asset not found");
        }

        Ci ci = ciRepository.findByTenant_IdAndAsset_Id(tenant.getId(), assetId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Host asset not found: " + assetId));

        List<CiAlias> aliases = filterAliases(ciAliasRepository.findByTenant_IdAndCi_IdOrderByAliasNameAsc(tenant.getId(), ci.getId()), sourceSystem);
        List<SoftwareInstance> software = filterSoftware(softwareInstanceRepository.findByCi_IdOrderByDisplayNameAsc(ci.getId()), sourceSystem);
        List<Finding> findings = findingRepository.findByAsset(ci.getAsset()).stream()
                .sorted(Comparator
                        .comparing((Finding finding) -> finding.getStatus() == FindingStatus.OPEN).reversed()
                        .thenComparing(Finding::getUpdatedAt, Comparator.nullsLast(Comparator.reverseOrder())))
                .toList();

        HostAssetSummaryResponse summary = summarizeHost(
                ci,
                Map.of(ci.getId(), aliases),
                Map.of(ci.getId(), software),
                Map.of(ci.getAsset().getId(), findings),
                sourceSystem
        );
        if (summary == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Host asset not found: " + assetId);
        }

        return new HostAssetDetailResponse(
                summary,
                aliases.stream().map(this::toAliasResponse).toList(),
                software.stream().map(this::toSoftwareResponse).toList(),
                findings.stream().map(this::toFindingResponse).toList()
        );
    }

    private HostAssetSummaryResponse summarizeHost(
            Ci ci,
            Map<UUID, List<CiAlias>> aliasesByCiId,
            Map<UUID, List<SoftwareInstance>> softwareByCiId,
            Map<UUID, List<Finding>> findingsByAssetId,
            String sourceSystem
    ) {
        Asset asset = ci.getAsset();
        if (asset == null || asset.getId() == null || ci.getId() == null) {
            return null;
        }

        List<CiAlias> aliases = filterAliases(aliasesByCiId.getOrDefault(ci.getId(), List.of()), sourceSystem);
        List<SoftwareInstance> software = filterSoftware(softwareByCiId.getOrDefault(ci.getId(), List.of()), sourceSystem);
        if (hasText(sourceSystem) && aliases.isEmpty() && software.isEmpty()) {
            return null;
        }

        List<Finding> findings = findingsByAssetId.getOrDefault(asset.getId(), List.of());
        long openFindingCount = findings.stream().filter(finding -> finding.getStatus() == FindingStatus.OPEN).count();
        int unresolvedReviewCount = unresolvedReviewCount(aliases, software);

        return new HostAssetSummaryResponse(
                asset.getId(),
                ci.getId(),
                asset.getName(),
                asset.getIdentifier(),
                ci.getSysId(),
                ci.getEnvironment(),
                ci.getOwnerEmail(),
                ci.getBusinessCriticality() == null ? null : ci.getBusinessCriticality().name(),
                asset.getState() == null ? null : asset.getState().name(),
                asset.getLastInventoryAt(),
                asset.getLastCmdbSyncAt(),
                aliases.size(),
                software.size(),
                Math.toIntExact(openFindingCount),
                findings.size(),
                unresolvedReviewCount
        );
    }

    private int unresolvedReviewCount(List<CiAlias> aliases, List<SoftwareInstance> software) {
        int count = 0;
        count += (int) aliases.stream().filter(HostInventoryReviewEvaluator::isLowConfidenceAlias).count();
        count += (int) software.stream().filter(HostInventoryReviewEvaluator::needsVersionReview).count();
        count += (int) software.stream().filter(HostInventoryReviewEvaluator::needsIdentityReview).count();
        count += (int) software.stream().filter(HostInventoryReviewEvaluator::needsDiscoveryModelReview).count();
        return count;
    }

    private List<CiAlias> filterAliases(List<CiAlias> aliases, String sourceSystem) {
        if (!hasText(sourceSystem)) {
            return aliases.stream()
                    .sorted(Comparator.comparing(CiAlias::getAliasName, Comparator.nullsLast(String::compareToIgnoreCase)))
                    .toList();
        }
        String normalizedSource = HostInventoryReviewEvaluator.normalize(sourceSystem);
        return aliases.stream()
                .filter(alias -> HostInventoryReviewEvaluator.normalize(alias.getSourceSystem()).equals(normalizedSource))
                .sorted(Comparator.comparing(CiAlias::getAliasName, Comparator.nullsLast(String::compareToIgnoreCase)))
                .toList();
    }

    private List<SoftwareInstance> filterSoftware(List<SoftwareInstance> software, String sourceSystem) {
        if (!hasText(sourceSystem)) {
            return software.stream()
                    .sorted(Comparator.comparing(SoftwareInstance::getDisplayName, Comparator.nullsLast(String::compareToIgnoreCase)))
                    .toList();
        }
        String normalizedSource = HostInventoryReviewEvaluator.normalize(sourceSystem);
        return software.stream()
                .filter(instance -> HostInventoryReviewEvaluator.normalize(instance.getSourceSystem()).equals(normalizedSource))
                .sorted(Comparator.comparing(SoftwareInstance::getDisplayName, Comparator.nullsLast(String::compareToIgnoreCase)))
                .toList();
    }

    private HostAliasResponse toAliasResponse(CiAlias alias) {
        return new HostAliasResponse(
                alias.getId(),
                alias.getAliasName(),
                alias.getSourceSystem(),
                alias.getConfidence(),
                alias.getFirstSeenAt(),
                alias.getLastSeenAt()
        );
    }

    private HostSoftwareInstanceResponse toSoftwareResponse(SoftwareInstance instance) {
        SoftwareIdentity identity = instance.getSoftwareIdentity();
        return new HostSoftwareInstanceResponse(
                instance.getId(),
                instance.getInventoryComponent() == null ? null : instance.getInventoryComponent().getId(),
                instance.getDisplayName(),
                instance.getPublisher(),
                instance.getVersion(),
                instance.getNormalizedPublisher(),
                instance.getNormalizedProduct(),
                instance.getNormalizedVersion(),
                instance.getSourceSystem(),
                instance.getVersionEvidence(),
                instance.isActiveInstall(),
                instance.isUnlicensedInstall(),
                instance.getInstallDate(),
                instance.getLastScanned(),
                instance.getLastUsed(),
                instance.getDiscoveryModelPk(),
                identity == null ? null : identity.getDisplayName(),
                identity == null ? null : identity.getCpe23(),
                HostInventoryReviewEvaluator.needsVersionReview(instance),
                HostInventoryReviewEvaluator.needsIdentityReview(instance),
                HostInventoryReviewEvaluator.needsDiscoveryModelReview(instance)
        );
    }

    private HostFindingResponse toFindingResponse(Finding finding) {
        return new HostFindingResponse(
                finding.getId(),
                finding.getVulnerability() == null ? null : finding.getVulnerability().getExternalId(),
                finding.getVulnerability() == null ? null : finding.getVulnerability().getSeverity(),
                finding.getStatus() == null ? null : finding.getStatus().name(),
                finding.getDecisionState() == null ? null : finding.getDecisionState().name(),
                finding.getRiskScore(),
                finding.getConfidenceScore(),
                finding.getMatchedBy(),
                finding.getFirstObservedAt(),
                finding.getLastObservedAt()
        );
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
