package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.OwnershipRule;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OwnershipRuleRequest;
import com.prototype.vulnwatch.dto.OwnershipRuleResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.OwnershipRuleRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OwnershipRuleService {

    private final OwnershipRuleRepository repository;
    private final FindingRepository findingRepository;
    private final FindingsScoreService findingsScoreService;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    public OwnershipRuleService(
            OwnershipRuleRepository repository,
            FindingRepository findingRepository,
            FindingsScoreService findingsScoreService,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.repository = repository;
        this.findingRepository = findingRepository;
        this.findingsScoreService = findingsScoreService;
        this.objectMapper = objectMapper;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @Transactional(readOnly = true)
    public List<OwnershipRuleResponse> list(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, repository::findAllByOrderByExecutionOrderAscCreatedAtAsc)
                .stream()
                .map(rule -> toResponse(rule, tenant))
                .toList();
    }

    @Transactional
    public OwnershipRuleResponse create(Tenant tenant, OwnershipRuleRequest request) {
        validateRequest(request);
        OwnershipRule rule = new OwnershipRule();
        rule.setTenant(tenant);
        rule.setName(request.name().trim());
        rule.setConditionJson(request.condition());
        rule.setUserGroup(request.userGroup().trim());
        rule.setExecutionOrder(request.executionOrder() != null ? request.executionOrder() : 0);
        return toResponse(repository.save(rule), tenant);
    }

    @Transactional
    public OwnershipRuleResponse update(UUID id, Tenant tenant, OwnershipRuleRequest request) {
        validateRequest(request);
        OwnershipRule rule = repository.findById(id)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership rule not found"));
        rule.setName(request.name().trim());
        rule.setConditionJson(request.condition());
        rule.setUserGroup(request.userGroup().trim());
        if (request.executionOrder() != null) {
            rule.setExecutionOrder(request.executionOrder());
        }
        rule.touch();
        return toResponse(repository.save(rule), tenant);
    }

    @Transactional
    public void delete(UUID id, Tenant tenant) {
        OwnershipRule rule = repository.findById(id)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership rule not found"));
        repository.delete(rule);
    }

    /**
     * Applies the first matching ownership rule to the finding, setting its ownerGroup.
     * Rules are evaluated in execution_order ascending, then createdAt ascending.
     * A finding with no matching rule retains whatever ownerGroup it already has.
     */
    public void applyOwnerGroupToFinding(Finding finding) {
        List<OwnershipRule> rules = tenantSchemaExecutionService.run(
                finding.getTenant(),
                repository::findAllByOrderByExecutionOrderAscCreatedAtAsc
        );
        applyOwnerGroupToFinding(finding, rules);
    }

    /**
     * Applies ownership rules to all findings for the tenant.
     * Returns the count of findings whose ownerGroup was changed.
     */
    @Transactional
    public int applyToAll(Tenant tenant) {
        List<OwnershipRule> rules = tenantSchemaExecutionService.run(
                tenant,
                repository::findAllByOrderByExecutionOrderAscCreatedAtAsc
        );
        if (rules.isEmpty()) {
            return 0;
        }
        return applyRulesToFindings(tenant, rules);
    }

    /**
     * Applies a single rule to all findings for the tenant.
     * Any finding matching the rule has its ownerGroup set to the rule's userGroup.
     * Returns the count of findings updated.
     */
    @Transactional
    public int applyRule(UUID ruleId, Tenant tenant) {
        OwnershipRule rule = repository.findById(ruleId)
                .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership rule not found"));
        return applyRulesToFindings(tenant, List.of(rule));
    }

    private int applyRulesToFindings(Tenant tenant, List<OwnershipRule> rules) {
        List<Finding> findings = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.findAllByOrderByUpdatedAtDesc()
        );
        List<Finding> changed = new ArrayList<>();
        for (Finding finding : findings) {
            String previous = finding.getOwnerGroup();
            applyOwnerGroupToFinding(finding, rules);
            if (!Objects.equals(previous, finding.getOwnerGroup())) {
                finding.touch();
                changed.add(finding);
            }
        }
        if (!changed.isEmpty()) {
            findingRepository.saveAll(changed);
        }
        return changed.size();
    }

    void applyOwnerGroupToFinding(Finding finding, List<OwnershipRule> rules) {
        for (OwnershipRule rule : rules) {
            String conditionsArray = extractConditionsArray(rule.getConditionJson());
            String logic = extractLogic(rule.getConditionJson());
            if (findingsScoreService.matchesSuppressionConditions(conditionsArray, logic, finding)) {
                finding.setOwnerGroup(rule.getUserGroup());
                return;
            }
        }
    }

    private String extractConditionsArray(String conditionJson) {
        try {
            var node = objectMapper.readTree(conditionJson);
            var conditionsNode = node.path("conditions");
            if (conditionsNode.isMissingNode()) {
                return "[]";
            }
            return objectMapper.writeValueAsString(conditionsNode);
        } catch (Exception e) {
            return "[]";
        }
    }

    private String extractLogic(String conditionJson) {
        try {
            var node = objectMapper.readTree(conditionJson);
            return node.path("logic").asText("AND");
        } catch (Exception e) {
            return "AND";
        }
    }

    private void validateRequest(OwnershipRuleRequest request) {
        if (request.name() == null || request.name().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "name is required");
        }
        if (request.userGroup() == null || request.userGroup().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "userGroup is required");
        }
    }

    private OwnershipRuleResponse toResponse(OwnershipRule rule, Tenant tenant) {
        long matchedCount = tenantSchemaExecutionService.run(
                tenant,
                () -> findingRepository.countByOwnerGroup(rule.getUserGroup())
        );
        return new OwnershipRuleResponse(
                rule.getId(),
                rule.getName(),
                rule.getConditionJson(),
                rule.getUserGroup(),
                rule.getExecutionOrder(),
                matchedCount,
                rule.getCreatedAt(),
                rule.getUpdatedAt()
        );
    }
}
