package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CveAiSolutionPersistenceService {

    private final OrgCveRecordRepository orgCveRecordRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;

    public CveAiSolutionPersistenceService(
            OrgCveRecordRepository orgCveRecordRepository,
            VulnerabilityRepository vulnerabilityRepository,
            RequestActorService requestActorService,
            TenantService tenantService
    ) {
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.requestActorService = requestActorService;
        this.tenantService = tenantService;
    }

    @Transactional
    public void saveAiSolution(String cveId, String contentJson) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
        record.setAiSolutionJson(contentJson);
        record.setAiSolutionGeneratedAt(Instant.now());
        record.touch();
        orgCveRecordRepository.save(record);
    }

    @Transactional(readOnly = true)
    public Optional<SavedAiSolution> getSavedAiSolution(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId).orElse(null);
        if (vulnerability == null) return Optional.empty();
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability).orElse(null);
        if (record == null || record.getAiSolutionJson() == null || record.getAiSolutionJson().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new SavedAiSolution(record.getAiSolutionJson(), record.getAiSolutionGeneratedAt()));
    }

    public record SavedAiSolution(String contentJson, Instant generatedAt) {}

    @Transactional
    public void saveAiActions(String cveId, String contentJson) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
        record.setAiActionsJson(contentJson);
        record.setAiActionsGeneratedAt(Instant.now());
        record.touch();
        orgCveRecordRepository.save(record);
    }

    @Transactional(readOnly = true)
    public Optional<SavedAiActions> getSavedAiActions(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId).orElse(null);
        if (vulnerability == null) return Optional.empty();
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability).orElse(null);
        if (record == null || record.getAiActionsJson() == null || record.getAiActionsJson().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(new SavedAiActions(record.getAiActionsJson(), record.getAiActionsGeneratedAt()));
    }

    public record SavedAiActions(String contentJson, Instant generatedAt) {}
}
