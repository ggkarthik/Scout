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
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class OwnershipRuleService {

    private final OwnershipRuleRepository repository;
    private final FindingRepository findingRepository;
    private final FindingsScoreService findingsScoreService;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private TransactionTemplate readTransactionTemplate;
    private TransactionTemplate writeTransactionTemplate;

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

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.readTransactionTemplate = null;
            this.writeTransactionTemplate = null;
            return;
        }
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public List<OwnershipRuleResponse> list(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> repository.findAllByOrderByExecutionOrderAscCreatedAtAsc()
                .stream()
                .map(this::toResponseInCurrentTenantSchema)
                .toList()));
    }

    public OwnershipRuleResponse create(Tenant tenant, OwnershipRuleRequest request) {
        validateRequest(request);
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            OwnershipRule rule = new OwnershipRule();
            rule.setTenant(tenant);
            rule.setName(request.name().trim());
            rule.setConditionJson(request.condition());
            rule.setUserGroup(request.userGroup().trim());
            rule.setExecutionOrder(request.executionOrder() != null ? request.executionOrder() : 0);
            return toResponseInCurrentTenantSchema(repository.save(rule));
        }));
    }

    public OwnershipRuleResponse update(UUID id, Tenant tenant, OwnershipRuleRequest request) {
        validateRequest(request);
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
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
            return toResponseInCurrentTenantSchema(repository.save(rule));
        }));
    }

    public void delete(UUID id, Tenant tenant) {
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            OwnershipRule rule = repository.findById(id)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership rule not found"));
            repository.delete(rule);
            return null;
        }));
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
    public int applyToAll(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            List<OwnershipRule> rules = repository.findAllByOrderByExecutionOrderAscCreatedAtAsc();
            if (rules.isEmpty()) {
                return 0;
            }
            return applyRulesToFindingsInCurrentTenantSchema(rules);
        }));
    }

    /**
     * Applies a single rule to all findings for the tenant.
     * Any finding matching the rule has its ownerGroup set to the rule's userGroup.
     * Returns the count of findings updated.
     */
    public int applyRule(UUID ruleId, Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            OwnershipRule rule = repository.findById(ruleId)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership rule not found"));
            return applyRulesToFindingsInCurrentTenantSchema(List.of(rule));
        }));
    }

    private int applyRulesToFindingsInCurrentTenantSchema(List<OwnershipRule> rules) {
        List<Finding> findings = findingRepository.findAllByOrderByUpdatedAtDesc();
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

    private OwnershipRuleResponse toResponseInCurrentTenantSchema(OwnershipRule rule) {
        long matchedCount = findingRepository.countByOwnerGroup(rule.getUserGroup());
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

    private <T> T executeRead(java.util.function.Supplier<T> work) {
        if (readTransactionTemplate == null) {
            return work.get();
        }
        T result = readTransactionTemplate.execute(status -> work.get());
        return result == null ? work.get() : result;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
