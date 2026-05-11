package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.RiskPolicy;
import java.time.Duration;
import java.time.Instant;
import org.springframework.stereotype.Service;

@Service
public class FindingSlaService {

    public Instant deriveDueAt(Instant firstObservedAt, double riskScore, Asset asset, RiskPolicy policy) {
        if (firstObservedAt == null || policy == null) {
            return null;
        }
        int baseSlaDays = baseSlaDaysForRisk(riskScore, policy);
        if (baseSlaDays <= 0) {
            return null;
        }
        double multiplier = assetMultiplier(asset, policy);
        long effectiveDays = Math.max(1, Math.round(baseSlaDays * multiplier));
        return firstObservedAt.plus(Duration.ofDays(effectiveDays));
    }

    private double assetMultiplier(Asset asset, RiskPolicy policy) {
        BusinessCriticality criticality = asset == null || asset.getBusinessCriticality() == null
                ? BusinessCriticality.MEDIUM
                : asset.getBusinessCriticality();
        return switch (criticality) {
            case CRITICAL -> policy.getAssetCriticalSlaMultiplier() > 0 ? policy.getAssetCriticalSlaMultiplier() : 1.0;
            case HIGH -> policy.getAssetHighSlaMultiplier() > 0 ? policy.getAssetHighSlaMultiplier() : 1.0;
            case MEDIUM -> policy.getAssetMediumSlaMultiplier() > 0 ? policy.getAssetMediumSlaMultiplier() : 1.0;
            case LOW -> policy.getAssetLowSlaMultiplier() > 0 ? policy.getAssetLowSlaMultiplier() : 1.0;
        };
    }

    private int baseSlaDaysForRisk(double riskScore, RiskPolicy policy) {
        if (riskScore >= policy.getCriticalThreshold()) {
            return policy.getCriticalSlaDays();
        }
        if (riskScore >= policy.getHighThreshold()) {
            return policy.getHighSlaDays();
        }
        if (riskScore >= 4.0) {
            return policy.getMediumSlaDays();
        }
        return policy.getLowSlaDays();
    }
}
