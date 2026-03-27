package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.RiskPolicy;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class FindingSlaServiceTest {

    private final FindingSlaService findingSlaService = new FindingSlaService();

    @Test
    void deriveDueAtAppliesSeverityWindowAndAssetMultiplier() {
        RiskPolicy policy = new RiskPolicy();
        policy.setCriticalThreshold(9.0);
        policy.setHighThreshold(7.0);
        policy.setCriticalSlaDays(7);
        policy.setHighSlaDays(14);
        policy.setMediumSlaDays(30);
        policy.setLowSlaDays(60);
        policy.setAssetCriticalSlaMultiplier(0.5);
        policy.setAssetHighSlaMultiplier(0.75);
        policy.setAssetMediumSlaMultiplier(1.0);
        policy.setAssetLowSlaMultiplier(1.25);

        Asset asset = new Asset();
        asset.setBusinessCriticality(BusinessCriticality.CRITICAL);
        Instant firstObservedAt = Instant.parse("2026-03-27T00:00:00Z");

        Instant dueAt = findingSlaService.deriveDueAt(firstObservedAt, 8.1, asset, policy);

        assertEquals(Instant.parse("2026-04-03T00:00:00Z"), dueAt);
    }
}
