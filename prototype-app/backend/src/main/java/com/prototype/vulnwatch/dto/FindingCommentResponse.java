package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record FindingCommentResponse(
        UUID id,
        String author,
        String body,
        Instant createdAt
) {
}
