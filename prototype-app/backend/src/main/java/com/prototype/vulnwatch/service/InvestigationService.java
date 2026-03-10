package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.InvestigationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class InvestigationService {

    private final InvestigationRepository investigationRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final TenantService tenantService;

    @Transactional(readOnly = true)
    public Investigation getInvestigation(Long tenantId, Long investigationId) {
        Tenant tenant = tenantService.resolveTenant(tenantId);
        return investigationRepository.findByIdAndTenantId(investigationId, tenant.getId())
                .orElseThrow(() -> new IllegalArgumentException("Investigation not found: " + investigationId));
    }

    @Transactional(readOnly = true)
    public List<Investigation> getInvestigationsByCve(Long tenantId, String cveId) {
        Tenant tenant = tenantService.resolveTenant(tenantId);
        return investigationRepository.findByTenantIdAndCveId(tenant.getId(), cveId);
    }

    @Transactional(readOnly = true)
    public Page<Investigation> getInvestigations(Long tenantId, Pageable pageable) {
        Tenant tenant = tenantService.resolveTenant(tenantId);
        return investigationRepository.findByTenantId(tenant.getId(), pageable);
    }

    @Transactional
    public Investigation createInvestigation(Long tenantId, String cveId, Investigation.InvestigationPriority priority, String createdBy) {
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("Vulnerability not found: " + cveId));
        Tenant tenant = tenantService.resolveTenant(tenantId);

        Investigation investigation = new Investigation();
        investigation.setVulnerability(vulnerability);
        investigation.setTenant(tenant);
        investigation.setStatus(Investigation.InvestigationStatus.OPEN);
        investigation.setPriority(priority != null ? priority : Investigation.InvestigationPriority.MEDIUM);
        investigation.setCreatedBy(createdBy);
        investigation.setModifiedBy(createdBy);

        // Add creation activity
        InvestigationActivity activity = new InvestigationActivity();
        activity.setActivityType(InvestigationActivity.ActivityType.CREATED);
        activity.setDescription("Investigation created");
        activity.setPerformedBy(createdBy);
        investigation.addActivity(activity);

        Investigation saved = investigationRepository.save(investigation);
        log.info("Created investigation {} for CVE {} by user {}", saved.getId(), cveId, createdBy);
        return saved;
    }

    @Transactional
    public Investigation updateInvestigation(Long tenantId, Long investigationId, InvestigationUpdateRequest request, String modifiedBy) {
        Investigation investigation = getInvestigation(tenantId, investigationId);

        boolean statusChanged = false;
        boolean priorityChanged = false;
        boolean assigned = false;

        if (request.getStatus() != null && !request.getStatus().equals(investigation.getStatus())) {
            Investigation.InvestigationStatus oldStatus = investigation.getStatus();
            investigation.setStatus(request.getStatus());
            statusChanged = true;

            if (request.getStatus() == Investigation.InvestigationStatus.CLOSED) {
                investigation.setClosedAt(Instant.now());
            }

            logActivity(investigation, InvestigationActivity.ActivityType.STATUS_CHANGED,
                    "Status changed from " + oldStatus + " to " + request.getStatus(), modifiedBy);
        }

        if (request.getPriority() != null && !request.getPriority().equals(investigation.getPriority())) {
            Investigation.InvestigationPriority oldPriority = investigation.getPriority();
            investigation.setPriority(request.getPriority());
            priorityChanged = true;

            logActivity(investigation, InvestigationActivity.ActivityType.PRIORITY_CHANGED,
                    "Priority changed from " + oldPriority + " to " + request.getPriority(), modifiedBy);
        }

        if (request.getAssignedTo() != null && !request.getAssignedTo().equals(investigation.getAssignedTo())) {
            investigation.setAssignedTo(request.getAssignedTo());
            assigned = true;

            logActivity(investigation, InvestigationActivity.ActivityType.ASSIGNED,
                    "Assigned to " + request.getAssignedTo(), modifiedBy);
        }

        if (request.getNotes() != null) {
            investigation.setNotes(request.getNotes());
            logActivity(investigation, InvestigationActivity.ActivityType.NOTES_UPDATED,
                    "Notes updated", modifiedBy);
        }

        if (request.getExploitAvailable() != null) {
            investigation.setExploitAvailable(request.getExploitAvailable());
        }

        if (request.getExploitDetails() != null) {
            investigation.setExploitDetails(request.getExploitDetails());
        }

        if (request.getPatchAvailable() != null) {
            investigation.setPatchAvailable(request.getPatchAvailable());
        }

        if (request.getPatchDetails() != null) {
            investigation.setPatchDetails(request.getPatchDetails());
        }

        if (request.getSystemsAffected() != null) {
            investigation.setSystemsAffected(request.getSystemsAffected());
        }

        if (request.getBusinessImpact() != null) {
            investigation.setBusinessImpact(request.getBusinessImpact());
        }

        if (request.getMitigationSteps() != null) {
            investigation.setMitigationSteps(request.getMitigationSteps());
        }

        if (request.getVulnReferences() != null) {
            investigation.setReferences(request.getVulnReferences());
        }

        investigation.setModifiedBy(modifiedBy);

        Investigation saved = investigationRepository.save(investigation);
        log.info("Updated investigation {} for CVE {} by user {}", investigationId,
                investigation.getVulnerability().getExternalId(), modifiedBy);
        return saved;
    }

    @Transactional
    public Investigation submitInvestigation(Long tenantId, String cveId, SubmitInvestigationRequest request, String userId) {
        Tenant tenant = tenantService.resolveTenant(tenantId);

        // Find the most recent non-closed investigation, or create a new one
        List<Investigation> existing = investigationRepository.findByTenantIdAndCveId(tenant.getId(), cveId);
        Investigation investigation = existing.stream()
                .filter(inv -> inv.getStatus() != Investigation.InvestigationStatus.CLOSED)
                .findFirst()
                .orElse(null);

        if (investigation == null) {
            Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                    .orElseThrow(() -> new IllegalArgumentException("Vulnerability not found: " + cveId));
            investigation = new Investigation();
            investigation.setVulnerability(vulnerability);
            investigation.setTenant(tenant);
            investigation.setCreatedBy(userId);

            InvestigationActivity activity = new InvestigationActivity();
            activity.setActivityType(InvestigationActivity.ActivityType.CREATED);
            activity.setDescription("Investigation created");
            activity.setPerformedBy(userId);
            investigation.addActivity(activity);
        }

        investigation.setStatus(Investigation.InvestigationStatus.IN_PROGRESS);
        investigation.setPriority(request.getPriority() != null ? request.getPriority() : Investigation.InvestigationPriority.MEDIUM);
        if (request.getNotes() != null) investigation.setNotes(request.getNotes());
        if (request.getAssignedTo() != null) investigation.setAssignedTo(request.getAssignedTo());
        investigation.setModifiedBy(userId);

        Investigation saved = investigationRepository.save(investigation);
        log.info("Submitted investigation {} for CVE {} by user {}", saved.getId(), cveId, userId);
        return investigationRepository.findByIdAndTenantId(saved.getId(), tenant.getId()).orElse(saved);
    }

    @Transactional
    public void deleteInvestigation(Long tenantId, Long investigationId) {
        Investigation investigation = getInvestigation(tenantId, investigationId);
        investigationRepository.delete(investigation);
        log.info("Deleted investigation {} for tenant {}", investigationId, tenantId);
    }

    private void logActivity(Investigation investigation, InvestigationActivity.ActivityType type,
                            String description, String performedBy) {
        InvestigationActivity activity = new InvestigationActivity();
        activity.setActivityType(type);
        activity.setDescription(description);
        activity.setPerformedBy(performedBy);
        investigation.addActivity(activity);
    }

    // DTO for single-call submit (create-or-update)
    @lombok.Data
    public static class SubmitInvestigationRequest {
        private Investigation.InvestigationPriority priority;
        private String assignedTo;
        private String notes;
    }

    // DTO for update requests
    @lombok.Data
    public static class InvestigationUpdateRequest {
        private Investigation.InvestigationStatus status;
        private Investigation.InvestigationPriority priority;
        private String assignedTo;
        private String notes;
        private Boolean exploitAvailable;
        private String exploitDetails;
        private Boolean patchAvailable;
        private String patchDetails;
        private String systemsAffected;
        private String businessImpact;
        private String mitigationSteps;
        private String vulnReferences;
    }
}
