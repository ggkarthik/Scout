package com.prototype.vulnwatch.dto;

import java.util.List;

public record AdvisoryRequest(
        String externalId,
        String title,
        String description,
        Double cvssScore,
        String severity,
        List<AdvisoryRuleRequest> rules
) {
}
