package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.BomContributionState;
import com.prototype.vulnwatch.domain.BomSource;
import com.prototype.vulnwatch.domain.BomSourceCompletenessAssertion;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomSourceResponse;
import com.prototype.vulnwatch.repo.BomComponentContributionRepository;
import com.prototype.vulnwatch.repo.BomSourceCompletenessAssertionRepository;
import com.prototype.vulnwatch.repo.BomSourceRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Read side for logical BOM sources.
 *
 * <p>Exists because replacement is no longer inferred: a caller wanting to replace a source
 * must name it, and until now there was no way to discover which sources an asset has.
 */
@Service
@RequiredArgsConstructor
public class BomSourceReadService {

    private final BomSourceRepository sourceRepository;
    private final BomComponentContributionRepository contributionRepository;
    private final BomSourceCompletenessAssertionRepository assertionRepository;

    @Transactional(readOnly = true)
    public List<BomSourceResponse> listSources(Tenant tenant, UUID assetId) {
        List<BomSource> sources = assetId == null
                ? sourceRepository.findAll()
                : sourceRepository.findByAssetId(assetId);
        return sources.stream().map(this::toResponse).toList();
    }

    private BomSourceResponse toResponse(BomSource source) {
        long supported = contributionRepository
                .findBySourceIdAndContributionState(source.getId(), BomContributionState.SUPPORTED)
                .size();
        long withdrawn = contributionRepository
                .findBySourceIdAndContributionState(source.getId(), BomContributionState.WITHDRAWN)
                .size();
        // The standing claim, which a replacement must repeat to stay in force.
        BomSourceCompletenessAssertion latest = assertionRepository
                .findFirstBySourceIdOrderByAssertedAtDesc(source.getId())
                .orElse(null);

        return new BomSourceResponse(
                source.getId(),
                source.getAssetId(),
                source.getBomType() == null ? null : source.getBomType().name(),
                source.getSupplier(),
                source.getSourceKey(),
                source.getSourceReference(),
                source.getCurrentBomId(),
                source.getRevision(),
                source.getCompleteness() == null ? null : source.getCompleteness().name(),
                source.getState() == null ? null : source.getState().name(),
                source.getCreatedAt(),
                source.getUpdatedAt(),
                supported,
                withdrawn,
                latest == null ? null : latest.getAssertedBy(),
                latest == null ? null : latest.getAssertedAt()
        );
    }
}
