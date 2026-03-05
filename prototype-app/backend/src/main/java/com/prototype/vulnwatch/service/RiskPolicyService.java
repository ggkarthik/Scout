package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.RiskPolicyRequest;
import com.prototype.vulnwatch.dto.RiskPolicyResponse;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class RiskPolicyService {

    private final RiskPolicyRepository riskPolicyRepository;
    private final RiskPolicySchemaService riskPolicySchemaService;

    public RiskPolicyService(
            RiskPolicyRepository riskPolicyRepository,
            RiskPolicySchemaService riskPolicySchemaService
    ) {
        this.riskPolicyRepository = riskPolicyRepository;
        this.riskPolicySchemaService = riskPolicySchemaService;
    }

    @Transactional
    public RiskPolicy getOrCreate(Tenant tenant) {
        riskPolicySchemaService.ensureColumns();
        return riskPolicyRepository.findByTenant(tenant)
                .orElseGet(() -> {
                    RiskPolicy policy = new RiskPolicy();
                    policy.setTenant(tenant);
                    return riskPolicyRepository.save(policy);
                });
    }

    @Transactional
    public RiskPolicyResponse update(Tenant tenant, RiskPolicyRequest req) {
        RiskPolicy policy = getOrCreate(tenant);

        if (req.cvssWeight() != null) {
            policy.setCvssWeight(req.cvssWeight());
        }
        if (req.kevBoost() != null) {
            policy.setKevBoost(req.kevBoost());
        }
        if (req.epssWeight() != null) {
            policy.setEpssWeight(req.epssWeight());
        }
        if (req.vexNotAffectedFreshnessDays() != null) {
            policy.setVexNotAffectedFreshnessDays(Math.max(1, req.vexNotAffectedFreshnessDays()));
        }
        if (req.vexFixedFreshnessDays() != null) {
            policy.setVexFixedFreshnessDays(Math.max(1, req.vexFixedFreshnessDays()));
        }
        if (req.vexKnownAffectedBoost() != null) {
            policy.setVexKnownAffectedBoost(Math.max(0.0, req.vexKnownAffectedBoost()));
        }
        if (req.vexUnderInvestigationPenalty() != null) {
            policy.setVexUnderInvestigationPenalty(Math.max(0.0, req.vexUnderInvestigationPenalty()));
        }
        if (req.vexNotAffectedReduction() != null) {
            policy.setVexNotAffectedReduction(Math.max(0.0, req.vexNotAffectedReduction()));
        }
        if (req.vexStalePenalty() != null) {
            policy.setVexStalePenalty(Math.max(0.0, req.vexStalePenalty()));
        }
        if (req.criticalThreshold() != null) {
            policy.setCriticalThreshold(req.criticalThreshold());
        }
        if (req.highThreshold() != null) {
            policy.setHighThreshold(req.highThreshold());
        }
        if (req.assetCriticalRiskBoost() != null) {
            policy.setAssetCriticalRiskBoost(req.assetCriticalRiskBoost());
        }
        if (req.assetHighRiskBoost() != null) {
            policy.setAssetHighRiskBoost(req.assetHighRiskBoost());
        }
        if (req.assetMediumRiskBoost() != null) {
            policy.setAssetMediumRiskBoost(req.assetMediumRiskBoost());
        }
        if (req.assetLowRiskBoost() != null) {
            policy.setAssetLowRiskBoost(req.assetLowRiskBoost());
        }
        if (req.criticalSlaDays() != null) {
            policy.setCriticalSlaDays(Math.max(0, req.criticalSlaDays()));
        }
        if (req.highSlaDays() != null) {
            policy.setHighSlaDays(Math.max(0, req.highSlaDays()));
        }
        if (req.mediumSlaDays() != null) {
            policy.setMediumSlaDays(Math.max(0, req.mediumSlaDays()));
        }
        if (req.lowSlaDays() != null) {
            policy.setLowSlaDays(Math.max(0, req.lowSlaDays()));
        }
        if (req.assetCriticalSlaMultiplier() != null) {
            policy.setAssetCriticalSlaMultiplier(Math.max(0.0, req.assetCriticalSlaMultiplier()));
        }
        if (req.assetHighSlaMultiplier() != null) {
            policy.setAssetHighSlaMultiplier(Math.max(0.0, req.assetHighSlaMultiplier()));
        }
        if (req.assetMediumSlaMultiplier() != null) {
            policy.setAssetMediumSlaMultiplier(Math.max(0.0, req.assetMediumSlaMultiplier()));
        }
        if (req.assetLowSlaMultiplier() != null) {
            policy.setAssetLowSlaMultiplier(Math.max(0.0, req.assetLowSlaMultiplier()));
        }
        if (req.autoCloseEnabled() != null) {
            policy.setAutoCloseEnabled(req.autoCloseEnabled());
        }
        if (req.autoCloseAssetIdentifier() != null) {
            String trimmed = req.autoCloseAssetIdentifier().trim();
            policy.setAutoCloseAssetIdentifier(trimmed.isEmpty() ? null : trimmed);
        }
        if (req.autoCloseAfterDays() != null) {
            policy.setAutoCloseAfterDays(Math.max(0, req.autoCloseAfterDays()));
        }

        policy.touch();
        return toResponse(riskPolicyRepository.save(policy));
    }

    public RiskPolicyResponse get(Tenant tenant) {
        return toResponse(getOrCreate(tenant));
    }

    private RiskPolicyResponse toResponse(RiskPolicy policy) {
        return new RiskPolicyResponse(
                policy.getCvssWeight(),
                policy.getKevBoost(),
                policy.getEpssWeight(),
                policy.getVexNotAffectedFreshnessDays(),
                policy.getVexFixedFreshnessDays(),
                policy.getVexKnownAffectedBoost(),
                policy.getVexUnderInvestigationPenalty(),
                policy.getVexNotAffectedReduction(),
                policy.getVexStalePenalty(),
                policy.getCriticalThreshold(),
                policy.getHighThreshold(),
                policy.getAssetCriticalRiskBoost(),
                policy.getAssetHighRiskBoost(),
                policy.getAssetMediumRiskBoost(),
                policy.getAssetLowRiskBoost(),
                policy.getCriticalSlaDays(),
                policy.getHighSlaDays(),
                policy.getMediumSlaDays(),
                policy.getLowSlaDays(),
                policy.getAssetCriticalSlaMultiplier(),
                policy.getAssetHighSlaMultiplier(),
                policy.getAssetMediumSlaMultiplier(),
                policy.getAssetLowSlaMultiplier(),
                policy.isAutoCloseEnabled(),
                policy.getAutoCloseAssetIdentifier(),
                policy.getAutoCloseAfterDays());
    }
}
