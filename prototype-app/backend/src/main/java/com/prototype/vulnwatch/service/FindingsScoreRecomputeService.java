package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Bulk-recomputes risk scores for all open findings of a tenant using the current
 * {@code findings_score_config} rules as the sole source of the risk score (0–10).
 */
@Service
public class FindingsScoreRecomputeService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingsScoreRecomputeService.class);

    private final FindingRepository findingRepository;
    private final RiskPolicyService riskPolicyService;
    private final FindingsScoreService findingsScoreService;
    private final FindingSlaService findingSlaService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TransactionTemplate writeTransactionTemplate;

    public FindingsScoreRecomputeService(
            FindingRepository findingRepository,
            RiskPolicyService riskPolicyService,
            FindingsScoreService findingsScoreService,
            FindingSlaService findingSlaService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            PlatformTransactionManager transactionManager
    ) {
        this.findingRepository = findingRepository;
        this.riskPolicyService = riskPolicyService;
        this.findingsScoreService = findingsScoreService;
        this.findingSlaService = findingSlaService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /**
     * Recomputes risk scores for all OPEN findings of the given tenant.
     *
     * @return number of findings updated
     */
    public int recomputeAll(Tenant tenant) {
        RiskPolicy policy = riskPolicyService.getOrCreate(tenant);
        String scoreConfig = policy.getFindingsScoreConfig();
        int updated = tenantSchemaExecutionService.run(tenant, () -> {
            Integer recomputed = writeTransactionTemplate.execute(
                    status -> recomputeAllInCurrentTenantSchema(policy, scoreConfig)
            );
            return recomputed == null ? 0 : recomputed;
        });
        LOG.info("FindingsScoreRecompute tenant={} updated={}", tenant.getName(), updated);
        return updated;
    }

    private int recomputeAllInCurrentTenantSchema(RiskPolicy policy, String scoreConfig) {
        List<Finding> openFindings = findingRepository.findByStatusOrderByUpdatedAtDesc(FindingStatus.OPEN);
        List<Finding> toSave = new ArrayList<>();
        for (Finding finding : openFindings) {
            if (finding.getVulnerability() == null
                    || finding.getAsset() == null
                    || finding.getComponent() == null) {
                continue;
            }

            double newRiskScore = findingsScoreService.computeFromParts(
                    scoreConfig,
                    finding.getVulnerability(),
                    finding.getAsset(),
                    finding.getComponent(),
                    finding.getSeverityOverride());

            finding.setRiskScore(newRiskScore);
            finding.setDueAt(findingSlaService.deriveDueAt(
                    finding.getFirstObservedAt(), newRiskScore, finding.getAsset(), policy));
            finding.touch();
            toSave.add(finding);
        }

        if (!toSave.isEmpty()) {
            findingRepository.saveAll(toSave);
        }
        return toSave.size();
    }
}
