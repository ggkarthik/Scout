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
        double multiplier = slaMultiplierForAsset(asset, policy);
        int effectiveDays = (int) Math.max(1, Math.round(baseSlaDays * multiplier));
        return firstObservedAt.plus(Duration.ofDays(effectiveDays));
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

    private double slaMultiplierForAsset(Asset asset, RiskPolicy policy) {
        BusinessCriticality criticality = asset == null || asset.getBusinessCriticality() == null
                ? BusinessCriticality.MEDIUM
                : asset.getBusinessCriticality();
        return switch (criticality) {
            case CRITICAL -> policy.getAssetCriticalSlaMultiplier();
            case HIGH -> policy.getAssetHighSlaMultiplier();
            case MEDIUM -> policy.getAssetMediumSlaMultiplier();
            case LOW -> policy.getAssetLowSlaMultiplier();
        };
    }
}
