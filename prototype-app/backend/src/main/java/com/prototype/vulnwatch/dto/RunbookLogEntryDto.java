package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record RunbookLogEntryDto(
        String id,
        String type,       // "NOTE" | "ACTION" | "IOC" | "AGENT"
        String message,
        String actor,      // analyst ID or "agent:<model>"
        String producedBy, // "ANALYST" | "AGENT"
        Instant at
) {}
