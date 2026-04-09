package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import com.prototype.vulnwatch.dto.SavedCveInvestigationSummaryResponse;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CveInvestigationSummaryPersistenceService {

    private final OrgCveRecordRepository orgCveRecordRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final RequestActorService requestActorService;
    private final TenantService tenantService;
    private final ObjectMapper objectMapper;

    public CveInvestigationSummaryPersistenceService(
            OrgCveRecordRepository orgCveRecordRepository,
            VulnerabilityRepository vulnerabilityRepository,
            RequestActorService requestActorService,
            TenantService tenantService,
            ObjectMapper objectMapper
    ) {
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.requestActorService = requestActorService;
        this.tenantService = tenantService;
        this.objectMapper = objectMapper;
    }

    @Transactional
    public void saveSummary(
            String cveId,
            Map<String, Object> input,
            CveInvestigationSummaryResponse summary,
            String mode
    ) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
        try {
            record.setInvestigationSummaryInputJson(objectMapper.writeValueAsString(input));
            record.setInvestigationSummaryOutputJson(objectMapper.writeValueAsString(summary));
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Unable to persist investigation summary.", error);
        }
        record.setInvestigationSummaryMode(mode);
        record.setInvestigationSummaryGeneratedAt(summary.generatedAt() == null ? Instant.now() : summary.generatedAt());
        record.touch();
        orgCveRecordRepository.save(record);
    }

    @Transactional(readOnly = true)
    public SavedCveInvestigationSummaryResponse getSavedSummary(String cveId) {
        Tenant tenant = tenantService.resolveTenantUuid(requestActorService.currentActor().tenantId());
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new EntityNotFoundException("Vulnerability not found: " + cveId));
        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseThrow(() -> new EntityNotFoundException("Org CVE record not found for: " + cveId));
        if (record.getInvestigationSummaryOutputJson() == null || record.getInvestigationSummaryOutputJson().isBlank()) {
            throw new EntityNotFoundException("No saved investigation summary found for: " + cveId);
        }
        try {
            Map<String, Object> input = objectMapper.readValue(
                    record.getInvestigationSummaryInputJson(),
                    new TypeReference<>() {}
            );
            CveInvestigationSummaryResponse summary = objectMapper.readValue(
                    record.getInvestigationSummaryOutputJson(),
                    CveInvestigationSummaryResponse.class
            );
            return new SavedCveInvestigationSummaryResponse(
                    record.getInvestigationSummaryMode(),
                    record.getInvestigationSummaryGeneratedAt(),
                    input,
                    summary
            );
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Saved investigation summary could not be parsed.", error);
        }
    }
}
