package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingComment;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.dto.FindingCommentRequest;
import com.prototype.vulnwatch.dto.FindingCommentResponse;
import com.prototype.vulnwatch.dto.FindingEventResponse;
import com.prototype.vulnwatch.dto.FindingTimelineResponse;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingCommentRepository;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingWorkflowService {

    private final FindingRepository findingRepository;
    private final FindingCommentRepository findingCommentRepository;
    private final FindingEventRepository findingEventRepository;
    private final RiskPolicyRepository riskPolicyRepository;
    private final AssetRepository assetRepository;
    private final ObjectMapper objectMapper;
    private final ObjectProvider<AuditEventService> auditEventServiceProvider;

    public FindingWorkflowService(
            FindingRepository findingRepository,
            FindingCommentRepository findingCommentRepository,
            FindingEventRepository findingEventRepository,
            RiskPolicyRepository riskPolicyRepository,
            AssetRepository assetRepository,
            ObjectMapper objectMapper,
            ObjectProvider<AuditEventService> auditEventServiceProvider
    ) {
        this.findingRepository = findingRepository;
        this.findingCommentRepository = findingCommentRepository;
        this.findingEventRepository = findingEventRepository;
        this.riskPolicyRepository = riskPolicyRepository;
        this.assetRepository = assetRepository;
        this.objectMapper = objectMapper;
        this.auditEventServiceProvider = auditEventServiceProvider;
    }

    @Transactional
    public Finding updateWorkflow(UUID findingId, FindingWorkflowUpdateRequest request) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        applyWorkflowUpdate(finding, request);
        finding.touch();
        audit("finding.workflow.updated", "finding", finding.getId().toString(), null);
        return findingRepository.save(finding);
    }

    @Transactional
    public int updateWorkflowBulk(List<Finding> findings, FindingWorkflowUpdateRequest request) {
        int updated = 0;
        for (Finding finding : findings) {
            applyWorkflowUpdate(finding, request);
            finding.touch();
            updated += 1;
        }
        if (!findings.isEmpty()) {
            findingRepository.saveAll(findings);
            audit("finding.workflow.bulk_updated", "finding", null,
                    "{\"updated\":" + updated + "}");
        }
        return updated;
    }

    @Transactional
    public int updateWorkflowBulkByIds(List<UUID> findingIds, FindingWorkflowUpdateRequest request) {
        return updateWorkflowBulk(findingRepository.findAllById(findingIds), request);
    }

    @Transactional
    public int bulkDelete(List<UUID> findingIds) {
        if (findingIds == null || findingIds.isEmpty()) {
            return 0;
        }
        List<Finding> findings = findingRepository.findAllById(findingIds);
        if (findings.isEmpty()) {
            return 0;
        }
        // Delete child records first to satisfy FK constraints
        for (Finding finding : findings) {
            findingCommentRepository.deleteAll(findingCommentRepository.findByFindingOrderByCreatedAtAsc(finding));
            findingEventRepository.deleteAll(findingEventRepository.findByFindingOrderByCreatedAtAsc(finding));
        }
        findingRepository.deleteAll(findings);
        audit("finding.bulk_deleted", "finding", null,
                "{\"deleted\":" + findings.size() + "}");
        return findings.size();
    }

    private void applyWorkflowUpdate(Finding finding, FindingWorkflowUpdateRequest request) {
        String actor = actor(request.actor());
        Instant now = Instant.now();

        if (request.assignedTo() != null) {
            String previousAssignee = finding.getAssignedTo();
            finding.setAssignedTo(trimToNull(request.assignedTo()));
            finding.setAssignedBy(actor);
            finding.setAssignedAt(now);
            finding.setDueAt(request.dueAt());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("previousAssignedTo", previousAssignee);
            details.put("assignedTo", finding.getAssignedTo());
            details.put("dueAt", finding.getDueAt());
            appendEvent(
                    finding,
                    "ASSIGNED",
                    actor,
                    "Finding assignment updated",
                    details);
        } else if (request.dueAt() != null) {
            finding.setDueAt(request.dueAt());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("dueAt", finding.getDueAt());
            appendEvent(
                    finding,
                    "DUE_DATE_UPDATED",
                    actor,
                    "Finding due date updated",
                    details);
        }

        if (request.status() != null && !request.status().isBlank()) {
            FindingStatus nextStatus = FindingStatus.valueOf(request.status().trim().toUpperCase());
            FindingStatus previousStatus = finding.getStatus();
            finding.setStatus(nextStatus);
            if (nextStatus == FindingStatus.SUPPRESSED) {
                finding.setSuppressionReason(trimToNull(request.suppressionReason()));
                finding.setSuppressedUntil(request.suppressedUntil());
            } else {
                finding.setSuppressionReason(null);
                finding.setSuppressedUntil(null);
                finding.setSuppressedByRuleId(null);
                finding.setSuppressedByRuleName(null);
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("from", previousStatus.name());
            details.put("to", nextStatus.name());
            details.put("suppressionReason", finding.getSuppressionReason());
            details.put("suppressedUntil", finding.getSuppressedUntil());
            appendEvent(
                    finding,
                    "STATUS_CHANGED",
                    actor,
                    "Finding status changed",
                    details);
        } else if (request.suppressionReason() != null || request.suppressedUntil() != null) {
            finding.setSuppressionReason(trimToNull(request.suppressionReason()));
            finding.setSuppressedUntil(request.suppressedUntil());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("suppressionReason", finding.getSuppressionReason());
            details.put("suppressedUntil", finding.getSuppressedUntil());
            appendEvent(
                    finding,
                    "SUPPRESSION_UPDATED",
                    actor,
                    "Suppression metadata updated",
                    details);
        }
    }

    private void audit(String action, String targetType, String targetId, String detailsJson) {
        AuditEventService auditEventService = auditEventServiceProvider.getIfAvailable();
        if (auditEventService != null) {
            auditEventService.record(action, targetType, targetId, detailsJson);
        }
    }

    @Transactional
    public FindingCommentResponse addComment(UUID findingId, FindingCommentRequest request) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        FindingComment comment = new FindingComment();
        comment.setFinding(finding);
        comment.setAuthor(request.author().trim());
        comment.setBody(request.body().trim());
        comment = findingCommentRepository.save(comment);
        appendEvent(
                finding,
                "COMMENT_ADDED",
                request.author().trim(),
                "Workflow comment added",
                Map.of("commentId", comment.getId()));
        return new FindingCommentResponse(comment.getId(), comment.getAuthor(), comment.getBody(), comment.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public FindingTimelineResponse getTimeline(UUID findingId) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        List<FindingEventResponse> events = findingEventRepository.findByFindingOrderByCreatedAtAsc(finding).stream()
                .map(event -> new FindingEventResponse(
                        event.getId(),
                        event.getEventType(),
                        event.getActor(),
                        event.getSummary(),
                        event.getDetailsJson(),
                        event.getCreatedAt()))
                .toList();
        List<FindingCommentResponse> comments = findingCommentRepository.findByFindingOrderByCreatedAtAsc(finding).stream()
                .map(comment -> new FindingCommentResponse(
                        comment.getId(),
                        comment.getAuthor(),
                        comment.getBody(),
                        comment.getCreatedAt()))
                .toList();
        return new FindingTimelineResponse(findingId, events, comments);
    }

    @Transactional
    public void appendEvent(Finding finding, String eventType, String actor, String summary, Map<String, Object> details) {
        FindingEvent event = new FindingEvent();
        event.setFinding(finding);
        event.setEventType(eventType);
        event.setActor(actor(actor));
        event.setSummary(summary);
        event.setDetailsJson(toJson(details));
        findingEventRepository.save(event);
    }

    @Scheduled(cron = "0 */15 * * * *")
    @Transactional
    public void reopenExpiredSuppressions() {
        Instant now = Instant.now();
        List<Finding> expired = findingRepository.findByStatusAndSuppressedUntilBefore(FindingStatus.SUPPRESSED, now);
        for (Finding finding : expired) {
            finding.setStatus(FindingStatus.OPEN);
            finding.setDecisionState(FindingDecisionState.AFFECTED);
            finding.setSuppressionReason(null);
            finding.setSuppressedUntil(null);
            finding.setSuppressedByRuleId(null);
            finding.setSuppressedByRuleName(null);
            finding.touch();
            appendEvent(
                    finding,
                    "SUPPRESSION_EXPIRED",
                    "system",
                    "Suppression expired and finding reopened",
                    Map.of("reopenedAt", now));
        }
        if (!expired.isEmpty()) {
            findingRepository.saveAll(expired);
        }
    }

    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void autoCloseFindingsByPolicy() {
        Instant now = Instant.now();
        List<RiskPolicy> policies = riskPolicyRepository.findAll();

        for (RiskPolicy policy : policies) {
            if (!policy.isAutoCloseEnabled()) {
                continue;
            }
            if (policy.getAutoCloseAfterDays() <= 0) {
                continue;
            }
            String identifier = trimToNull(policy.getAutoCloseAssetIdentifier());
            if (identifier == null) {
                continue;
            }

            Asset asset = assetRepository.findByTenantAndIdentifier(policy.getTenant(), identifier).orElse(null);
            if (asset == null) {
                continue;
            }

            Instant cutoff = now.minus(Duration.ofDays(policy.getAutoCloseAfterDays()));
            List<Finding> findings = findingRepository.findByAsset(asset);
            List<Finding> toPersist = new ArrayList<>();
            for (Finding finding : findings) {
                if (finding.getStatus() == FindingStatus.AUTO_CLOSED) {
                    continue;
                }
                Instant firstObservedAt = finding.getFirstObservedAt();
                if (firstObservedAt == null || firstObservedAt.isAfter(cutoff)) {
                    continue;
                }

                FindingStatus previousStatus = finding.getStatus();
                finding.setStatus(FindingStatus.AUTO_CLOSED);
                finding.setSuppressionReason(null);
                finding.setSuppressedUntil(null);
                finding.touch();
                appendEvent(
                        finding,
                        "AUTO_CLOSED_POLICY",
                        "system",
                        "Finding auto-closed by asset policy",
                        Map.of(
                                "assetIdentifier", identifier,
                                "cutoffAt", cutoff,
                                "autoCloseAfterDays", policy.getAutoCloseAfterDays(),
                                "fromStatus", previousStatus.name(),
                                "toStatus", FindingStatus.AUTO_CLOSED.name()
                        ));
                toPersist.add(finding);
            }
            if (!toPersist.isEmpty()) {
                findingRepository.saveAll(toPersist);
            }
        }
    }

    private String actor(String actor) {
        return actor == null || actor.isBlank() ? "system" : actor.trim();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }
}
