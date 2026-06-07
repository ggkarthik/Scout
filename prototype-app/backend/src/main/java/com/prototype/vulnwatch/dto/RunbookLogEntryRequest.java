package com.prototype.vulnwatch.dto;

public record RunbookLogEntryRequest(
        String type,      // "NOTE" | "ACTION" | "IOC" | "AGENT"
        String message,
        String actor,
        String producedBy // "ANALYST" | "AGENT"
) {}
