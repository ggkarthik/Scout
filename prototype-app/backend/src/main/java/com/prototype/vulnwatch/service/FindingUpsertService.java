package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.Objects;
import java.util.UUID;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingUpsertService {

    private final FindingRepository findingRepository;

    public FindingUpsertService(FindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    @Transactional
    public UpsertResult upsert(Finding candidate, ExistingFindingMutator existingFindingMutator) {
        Objects.requireNonNull(candidate, "candidate");
        Objects.requireNonNull(existingFindingMutator, "existingFindingMutator");

        UUID componentId = requireId(candidate.getComponent() == null ? null : candidate.getComponent().getId(), "component");
        UUID vulnerabilityId = requireId(candidate.getVulnerability() == null ? null : candidate.getVulnerability().getId(), "vulnerability");

        Finding existing = findingRepository.findFirstByComponent_IdAndVulnerability_Id(componentId, vulnerabilityId)
                .orElse(null);
        if (existing == null) {
            try {
                Finding created = findingRepository.saveAndFlush(candidate);
                return new UpsertResult(created, UpsertAction.CREATED);
            } catch (DataIntegrityViolationException race) {
                existing = findingRepository.findFirstByComponent_IdAndVulnerability_Id(componentId, vulnerabilityId)
                        .orElseThrow(() -> race);
            }
        }

        UpsertAction action = existingFindingMutator.apply(existing);
        if (action == UpsertAction.CREATED) {
            action = UpsertAction.UPDATED;
        }
        if (action != UpsertAction.UNCHANGED) {
            existing = findingRepository.save(existing);
        }
        return new UpsertResult(existing, action);
    }

    private UUID requireId(UUID id, String label) {
        if (id == null) {
            throw new IllegalArgumentException("Finding candidate requires " + label + " id");
        }
        return id;
    }

    @FunctionalInterface
    public interface ExistingFindingMutator {
        UpsertAction apply(Finding finding);
    }

    public enum UpsertAction {
        CREATED,
        REOPENED,
        UPDATED,
        UNCHANGED
    }

    public record UpsertResult(Finding finding, UpsertAction action) {
    }
}
