package com.prototype.vulnwatch.dto;

import java.util.List;

public record FindingFilterValuesResponse(
        List<String> severities,
        List<String> statuses,
        List<String> decisionStates,
        List<String> matchMethods,
        List<String> vexStatuses,
        List<String> vexFreshness,
        List<String> vexProviders
) {
}
