package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AiBomDeclaredResource;
import com.prototype.vulnwatch.domain.AiBomResourceVulnerabilityLink;
import com.prototype.vulnwatch.dto.AffectedAiResourceSummary;
import com.prototype.vulnwatch.repo.AiBomDeclaredResourceRepository;
import com.prototype.vulnwatch.repo.AiBomResourceVulnerabilityLinkRepository;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Batch-resolves, for an already paginated page of findings, which declared AI-BOM resources
 * each one transitively affects (Milestone 3 part 5.1). Two queries total regardless of page
 * size -- never one query per finding, and never a join into the findings query itself, which
 * would multiply rows ahead of pagination.
 */
@Service
@RequiredArgsConstructor
public class AiBomAffectedResourceSummaryService {

    private final AiBomResourceVulnerabilityLinkRepository linkRepository;
    private final AiBomDeclaredResourceRepository declaredResourceRepository;

    public Map<UUID, List<AffectedAiResourceSummary>> summarize(Collection<UUID> findingIds) {
        if (findingIds == null || findingIds.isEmpty()) {
            return Map.of();
        }
        List<AiBomResourceVulnerabilityLink> links = linkRepository.findByFindingIdIn(findingIds);
        if (links.isEmpty()) {
            return Map.of();
        }

        Map<UUID, AiBomDeclaredResource> resourcesById = new LinkedHashMap<>();
        for (AiBomDeclaredResource resource : declaredResourceRepository.findAllById(
                links.stream().map(AiBomResourceVulnerabilityLink::getDeclaredResourceId).distinct().toList())) {
            resourcesById.put(resource.getId(), resource);
        }

        Map<UUID, List<AffectedAiResourceSummary>> summaries = new LinkedHashMap<>();
        for (AiBomResourceVulnerabilityLink link : links) {
            AiBomDeclaredResource resource = resourcesById.get(link.getDeclaredResourceId());
            if (resource == null) {
                continue;
            }
            summaries.computeIfAbsent(link.getFindingId(), ignored -> new java.util.ArrayList<>())
                    .add(new AffectedAiResourceSummary(
                            resource.getId(), resource.getName(), resource.getResourceKind().name()));
        }
        return summaries;
    }
}
