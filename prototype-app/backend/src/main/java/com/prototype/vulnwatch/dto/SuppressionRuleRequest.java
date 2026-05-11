package com.prototype.vulnwatch.dto;

public record SuppressionRuleRequest(
        String name,
        String state,
        String recordType,
        String conditionsJson,
        String conditionLogic,
        String reason,
        String validFrom,
        String validTo
) {
}
