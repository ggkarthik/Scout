package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;

public record FindingTimelineResponse(
        UUID findingId,
        List<FindingEventResponse> events,
        List<FindingCommentResponse> comments
) {
}
