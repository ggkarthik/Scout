package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.OrgCveAiArtifact;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import com.prototype.vulnwatch.dto.SavedCveInvestigationSummaryResponse;
import com.prototype.vulnwatch.repo.OrgCveAiArtifactRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class CveInvestigationSummaryPersistenceService {

    private final OrgCveRecordRepository orgCveRecordRepository;
    private final OrgCveAiArtifactRepository orgCveAiArtifactRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private TransactionTemplate writeTransactionTemplate;

    public CveInvestigationSummaryPersistenceService(
            OrgCveRecordRepository orgCveRecordRepository,
            OrgCveAiArtifactRepository orgCveAiArtifactRepository,
            VulnerabilityRepository vulnerabilityRepository,
            RequestActorService requestActorService,
            TenantService tenantService,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.orgCveAiArtifactRepository = orgCveAiArtifactRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.requestActorService = requestActorService;
        this.tenantService = tenantService;
        this.objectMapper = objectMapper;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            return;
        }
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public void saveSummary(
            String cveId,
            Map<String, Object> input,
            CveInvestigationSummaryResponse summary,
            String mode
    ) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            OrgCveRecord record = orgCveRecordRepository.findByVulnerability(vulnerability)
                    .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
            OrgCveAiArtifact artifact = orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId())
                    .orElseGet(() -> newArtifact(record));
            try {
                artifact.setInvestigationSummaryInputJson(objectMapper.writeValueAsString(input));
                artifact.setInvestigationSummaryOutputJson(objectMapper.writeValueAsString(summary));
            } catch (JsonProcessingException error) {
                throw new IllegalStateException("Unable to persist investigation summary.", error);
            }
            artifact.setInvestigationSummaryMode(mode);
            artifact.setInvestigationSummaryGeneratedAt(summary.generatedAt() == null ? Instant.now() : summary.generatedAt());
            artifact.touch();
            orgCveAiArtifactRepository.save(artifact);
            record.touch();
            orgCveRecordRepository.save(record);
            return null;
        }));
    }

    public SavedCveInvestigationSummaryResponse getSavedSummary(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        OrgCveAiArtifact artifact = tenantSchemaExecutionService.run(tenant, () -> {
            OrgCveRecord record = orgCveRecordRepository.findByVulnerability(vulnerability)
                    .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
            return orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId())
                    .orElseThrow(() -> new EntityNotFoundException("No saved investigation summary found for: " + cveId));
        });
        if (artifact.getInvestigationSummaryOutputJson() == null || artifact.getInvestigationSummaryOutputJson().isBlank()) {
            throw new EntityNotFoundException("No saved investigation summary found for: " + cveId);
        }
        try {
            Map<String, Object> input = objectMapper.readValue(
                    artifact.getInvestigationSummaryInputJson(),
                    new TypeReference<>() {}
            );
            CveInvestigationSummaryResponse summary = objectMapper.readValue(
                    artifact.getInvestigationSummaryOutputJson(),
                    CveInvestigationSummaryResponse.class
            );
            return new SavedCveInvestigationSummaryResponse(
                    artifact.getInvestigationSummaryMode(),
                    artifact.getInvestigationSummaryGeneratedAt(),
                    input,
                    summary
            );
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Saved investigation summary could not be parsed.", error);
        }
    }

    private OrgCveAiArtifact newArtifact(OrgCveRecord record) {
        OrgCveAiArtifact artifact = new OrgCveAiArtifact();
        artifact.setOrgCveRecord(record);
        return artifact;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
