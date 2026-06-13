package com.prototype.vulnwatch.dto;

import java.util.List;

public record OperationalDemoPurgeDryRunResponse(
        boolean available,
        long totalCandidates,
        List<OperationalDemoPurgeDryRunCandidateResponse> candidates
) {
}
