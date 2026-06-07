package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record RunbookLogEntryResponse(
        String id,
        String type,
        String message,
        String actor,
        String producedBy,
        Instant at
) {}
