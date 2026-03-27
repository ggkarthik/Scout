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
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
public class InvestigationService {

    private final InvestigationRepository investigationRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final TenantService tenantService;

    @Transactional(readOnly = true)
    public Investigation getInvestigation(Long tenantId, Long investigationId) {
        return getInvestigation(resolveTenant(tenantId), investigationId);
    }

    @Transactional(readOnly = true)
    public Investigation getInvestigation(UUID tenantId, Long investigationId) {
        return getInvestigation(resolveTenant(tenantId), investigationId);
    }

    @Transactional(readOnly = true)
    public List<Investigation> getInvestigationsByCve(Long tenantId, String cveId) {
        return getInvestigationsByCve(resolveTenant(tenantId), cveId);
    }

    @Transactional(readOnly = true)
    public List<Investigation> getInvestigationsByCve(UUID tenantId, String cveId) {
        return getInvestigationsByCve(resolveTenant(tenantId), cveId);
    }

    @Transactional(readOnly = true)
    public Page<Investigation> getInvestigations(Long tenantId, Pageable pageable) {
        return getInvestigations(resolveTenant(tenantId), pageable);
    }

    @Transactional(readOnly = true)
    public Page<Investigation> getInvestigations(UUID tenantId, Pageable pageable) {
        return getInvestigations(resolveTenant(tenantId), pageable);
    }

    @Transactional
    public Investigation createInvestigation(Long tenantId, String cveId, Investigation.InvestigationPriority priority, String createdBy) {
        return createInvestigation(resolveTenant(tenantId), cveId, priority, createdBy);
    }

    @Transactional
    public Investigation createInvestigation(UUID tenantId, String cveId, Investigation.InvestigationPriority priority, String createdBy) {
        return createInvestigation(resolveTenant(tenantId), cveId, priority, createdBy);
    }

    @Transactional
    public Investigation updateInvestigation(Long tenantId, Long investigationId, InvestigationUpdateRequest request, String modifiedBy) {
        Investigation investigation = getInvestigation(tenantId, investigationId);
        return updateInvestigation(investigation, investigationId, request, modifiedBy);
    }

    @Transactional
    public Investigation updateInvestigation(UUID tenantId, Long investigationId, InvestigationUpdateRequest request, String modifiedBy) {
        Investigation investigation = getInvestigation(tenantId, investigationId);
        return updateInvestigation(investigation, investigationId, request, modifiedBy);
    }

    @Transactional
    public Investigation submitInvestigation(Long tenantId, String cveId, SubmitInvestigationRequest request, String userId) {
        return submitInvestigation(resolveTenant(tenantId), cveId, request, userId);
    }

    @Transactional
    public Investigation submitInvestigation(UUID tenantId, String cveId, SubmitInvestigationRequest request, String userId) {
        return submitInvestigation(resolveTenant(tenantId), cveId, request, userId);
    }

    @Transactional
    public void deleteInvestigation(Long tenantId, Long investigationId) {
        deleteInvestigation(resolveTenant(tenantId), investigationId);
    }

    @Transactional
    public void deleteInvestigation(UUID tenantId, Long investigationId) {
        deleteInvestigation(resolveTenant(tenantId), investigationId);
    }

    private Investigation getInvestigation(Tenant tenant, Long investigationId) {
        return investigationRepository.findByIdAndTenantId(investigationId, tenant.getId())
                .orElseThrow(() -> new IllegalArgumentException("Investigation not found: " + investigationId));
    }

    private List<Investigation> getInvestigationsByCve(Tenant tenant, String cveId) {
        return investigationRepository.findByTenantIdAndCveId(tenant.getId(), cveId);
    }

    private Page<Investigation> getInvestigations(Tenant tenant, Pageable pageable) {
        return investigationRepository.findByTenantId(tenant.getId(), pageable);
    }

    private Investigation createInvestigation(Tenant tenant, String cveId, Investigation.InvestigationPriority priority, String createdBy) {
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new IllegalArgumentException("Vulnerability not found: " + cveId));

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

    private Investigation updateInvestigation(Investigation investigation, Long investigationId, InvestigationUpdateRequest request, String modifiedBy) {
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

    private Investigation submitInvestigation(Tenant tenant, String cveId, SubmitInvestigationRequest request, String userId) {
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

    private void deleteInvestigation(Tenant tenant, Long investigationId) {
        Investigation investigation = getInvestigation(tenant, investigationId);
        investigationRepository.delete(investigation);
        log.info("Deleted investigation {} for tenant {}", investigationId, tenant.getId());
    }

    private void logActivity(Investigation investigation, InvestigationActivity.ActivityType type,
                            String description, String performedBy) {
        InvestigationActivity activity = new InvestigationActivity();
        activity.setActivityType(type);
        activity.setDescription(description);
        activity.setPerformedBy(performedBy);
        investigation.addActivity(activity);
    }

    private Tenant resolveTenant(Long tenantId) {
        return tenantService.resolveTenant(tenantId);
    }

    private Tenant resolveTenant(UUID tenantId) {
        return tenantService.resolveTenantUuid(tenantId);
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
