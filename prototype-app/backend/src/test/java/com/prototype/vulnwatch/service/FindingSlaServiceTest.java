package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.RiskPolicy;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class FindingSlaServiceTest {

    private final FindingSlaService findingSlaService = new FindingSlaService();
    private static final Instant T0 = Instant.parse("2026-03-27T00:00:00Z");

    private RiskPolicy defaultPolicy() {
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
        return policy;
    }

    private Asset assetWithCriticality(BusinessCriticality criticality) {
        Asset asset = new Asset();
        asset.setBusinessCriticality(criticality);
        return asset;
    }

    @Test
    void deriveDueAtAppliesSeverityWindowAndAssetMultiplier() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                8.1,
                assetWithCriticality(BusinessCriticality.CRITICAL),
                defaultPolicy()
        );

        // high SLA = 14 days, critical multiplier = 0.5 → 7 days
        assertEquals(T0.plus(Duration.ofDays(7)), dueAt);
    }

    @Test
    void deriveDueAtReturnsNullWhenFirstObservedAtIsNull() {
        assertNull(findingSlaService.deriveDueAt(
                null,
                8.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        ));
    }

    @Test
    void deriveDueAtReturnsNullWhenPolicyIsNull() {
        assertNull(findingSlaService.deriveDueAt(
                T0,
                8.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                null
        ));
    }

    @Test
    void deriveDueAtReturnsNullWhenBaseSlaDaysIsZero() {
        RiskPolicy policy = defaultPolicy();
        policy.setLowSlaDays(0);

        // riskScore 1.0 falls into the low bucket
        assertNull(findingSlaService.deriveDueAt(
                T0,
                1.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                policy
        ));
    }

    @Test
    void deriveDueAtReturnsNullWhenBaseSlaDaysIsNegative() {
        RiskPolicy policy = defaultPolicy();
        policy.setMediumSlaDays(-5);

        assertNull(findingSlaService.deriveDueAt(
                T0,
                5.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                policy
        ));
    }

    @Test
    void deriveDueAtUsesCriticalSlaWhenScoreAtOrAboveCriticalThreshold() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                9.5,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        );

        // critical SLA = 7 days, medium multiplier = 1.0
        assertEquals(T0.plus(Duration.ofDays(7)), dueAt);
    }

    @Test
    void deriveDueAtUsesCriticalSlaAtExactCriticalThreshold() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                9.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        );

        assertEquals(T0.plus(Duration.ofDays(7)), dueAt);
    }

    @Test
    void deriveDueAtUsesHighSlaAtExactHighThreshold() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                7.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        );

        assertEquals(T0.plus(Duration.ofDays(14)), dueAt);
    }

    @Test
    void deriveDueAtUsesMediumSlaAtScoreFour() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                4.0,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        );

        assertEquals(T0.plus(Duration.ofDays(30)), dueAt);
    }

    @Test
    void deriveDueAtUsesMediumSlaForMidRangeScore() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                5.5,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        );

        assertEquals(T0.plus(Duration.ofDays(30)), dueAt);
    }

    @Test
    void deriveDueAtUsesLowSlaWhenScoreBelowFour() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                3.9,
                assetWithCriticality(BusinessCriticality.MEDIUM),
                defaultPolicy()
        );

        assertEquals(T0.plus(Duration.ofDays(60)), dueAt);
    }

    @Test
    void deriveDueAtUsesHighAssetMultiplier() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                8.0,
                assetWithCriticality(BusinessCriticality.HIGH),
                defaultPolicy()
        );

        // high SLA = 14 * 0.75 = 10.5 → rounded to 11 days
        assertEquals(T0.plus(Duration.ofDays(11)), dueAt);
    }

    @Test
    void deriveDueAtUsesLowAssetMultiplier() {
        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                8.0,
                assetWithCriticality(BusinessCriticality.LOW),
                defaultPolicy()
        );

        // high SLA = 14 * 1.25 = 17.5 → rounded to 18 days
        assertEquals(T0.plus(Duration.ofDays(18)), dueAt);
    }

    @Test
    void deriveDueAtTreatsNullAssetAsMediumCriticality() {
        Instant dueAt = findingSlaService.deriveDueAt(T0, 8.0, null, defaultPolicy());

        // high SLA 14 * medium multiplier 1.0
        assertEquals(T0.plus(Duration.ofDays(14)), dueAt);
    }

    @Test
    void deriveDueAtTreatsNullCriticalityAsMedium() {
        Asset asset = new Asset();
        asset.setBusinessCriticality(null);

        Instant dueAt = findingSlaService.deriveDueAt(T0, 8.0, asset, defaultPolicy());

        assertEquals(T0.plus(Duration.ofDays(14)), dueAt);
    }

    @Test
    void deriveDueAtFloorsEffectiveDaysAtOneWhenMultiplierWouldRoundToZero() {
        RiskPolicy policy = defaultPolicy();
        policy.setCriticalSlaDays(1);
        policy.setAssetCriticalSlaMultiplier(0.1);

        Instant dueAt = findingSlaService.deriveDueAt(
                T0,
                9.5,
                assetWithCriticality(BusinessCriticality.CRITICAL),
                policy
        );

        // 1 * 0.1 = 0.1 → Math.round = 0 → floored to 1 day
        assertEquals(T0.plus(Duration.ofDays(1)), dueAt);
    }
}
