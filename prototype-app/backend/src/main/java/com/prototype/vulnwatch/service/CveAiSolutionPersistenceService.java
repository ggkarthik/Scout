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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class CveAiSolutionPersistenceService {

    private final OrgCveRecordRepository orgCveRecordRepository;
    private final OrgCveAiArtifactRepository orgCveAiArtifactRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private TransactionTemplate writeTransactionTemplate;

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

    public void saveAiSolution(String cveId, String contentJson) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
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
            return null;
        }));
    }

    public Optional<SavedAiSolution> getSavedAiSolution(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId).orElse(null);
        if (vulnerability == null) return Optional.empty();
        return tenantSchemaExecutionService.run(tenant, () -> orgCveRecordRepository.findByVulnerability(vulnerability)
                .flatMap(record -> orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId()))
                .filter(artifact -> artifact.getAiSolutionJson() != null && !artifact.getAiSolutionJson().isBlank())
                .map(artifact -> new SavedAiSolution(artifact.getAiSolutionJson(), artifact.getAiSolutionGeneratedAt())));
    }

    public record SavedAiSolution(String contentJson, Instant generatedAt) {}

    public void saveAiActions(String cveId, String contentJson) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
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
            return null;
        }));
    }

    public Optional<SavedAiActions> getSavedAiActions(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId).orElse(null);
        if (vulnerability == null) return Optional.empty();
        return tenantSchemaExecutionService.run(tenant, () -> orgCveRecordRepository.findByVulnerability(vulnerability)
                .flatMap(record -> orgCveAiArtifactRepository.findByOrgCveRecordId(record.getId()))
                .filter(artifact -> artifact.getAiActionsJson() != null && !artifact.getAiActionsJson().isBlank())
                .map(artifact -> new SavedAiActions(artifact.getAiActionsJson(), artifact.getAiActionsGeneratedAt())));
    }

    public record SavedAiActions(String contentJson, Instant generatedAt) {}

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
