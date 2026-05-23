package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.OrgCveAiArtifact;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.OrgCveAiArtifactRepository;
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
    private final OrgCveAiArtifactRepository orgCveAiArtifactRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public CveAiSolutionPersistenceService(
            OrgCveRecordRepository orgCveRecordRepository,
            OrgCveAiArtifactRepository orgCveAiArtifactRepository,
            VulnerabilityRepository vulnerabilityRepository,
            RequestActorService requestActorService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.orgCveAiArtifactRepository = orgCveAiArtifactRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.requestActorService = requestActorService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional
    public void saveAiSolution(String cveId, String contentJson) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        tenantSchemaExecutionService.run(tenant, () -> {
            OrgCveRecord record = orgCveRecordRepository.findByVulnerability(vulnerability)
                    .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
            OrgCveAiArtifact artifact = orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId())
                    .orElseGet(() -> newArtifact(record));
            artifact.setAiSolutionJson(contentJson);
            artifact.setAiSolutionGeneratedAt(Instant.now());
            artifact.touch();
            orgCveAiArtifactRepository.save(artifact);
            record.touch();
            orgCveRecordRepository.save(record);
        });
    }

    @Transactional(readOnly = true)
    public Optional<SavedAiSolution> getSavedAiSolution(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId).orElse(null);
        if (vulnerability == null) return Optional.empty();
        OrgCveRecord record = tenantSchemaExecutionService.run(tenant, () -> orgCveRecordRepository.findByVulnerability(vulnerability))
                .orElse(null);
        if (record == null) {
            return Optional.empty();
        }
        return orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId())
                .filter(artifact -> artifact.getAiSolutionJson() != null && !artifact.getAiSolutionJson().isBlank())
                .map(artifact -> new SavedAiSolution(artifact.getAiSolutionJson(), artifact.getAiSolutionGeneratedAt()));
    }

    public record SavedAiSolution(String contentJson, Instant generatedAt) {}

    @Transactional
    public void saveAiActions(String cveId, String contentJson) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        tenantSchemaExecutionService.run(tenant, () -> {
            OrgCveRecord record = orgCveRecordRepository.findByVulnerability(vulnerability)
                    .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
            OrgCveAiArtifact artifact = orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId())
                    .orElseGet(() -> newArtifact(record));
            artifact.setAiActionsJson(contentJson);
            artifact.setAiActionsGeneratedAt(Instant.now());
            artifact.touch();
            orgCveAiArtifactRepository.save(artifact);
            record.touch();
            orgCveRecordRepository.save(record);
        });
    }

    @Transactional(readOnly = true)
    public Optional<SavedAiActions> getSavedAiActions(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId).orElse(null);
        if (vulnerability == null) return Optional.empty();
        OrgCveRecord record = tenantSchemaExecutionService.run(tenant, () -> orgCveRecordRepository.findByVulnerability(vulnerability))
                .orElse(null);
        if (record == null) {
            return Optional.empty();
        }
        return orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId())
                .filter(artifact -> artifact.getAiActionsJson() != null && !artifact.getAiActionsJson().isBlank())
                .map(artifact -> new SavedAiActions(artifact.getAiActionsJson(), artifact.getAiActionsGeneratedAt()));
    }

    public record SavedAiActions(String contentJson, Instant generatedAt) {}

    private OrgCveAiArtifact newArtifact(OrgCveRecord record) {
        OrgCveAiArtifact artifact = new OrgCveAiArtifact();
        artifact.setOrgCveRecord(record);
        return artifact;
    }
}
