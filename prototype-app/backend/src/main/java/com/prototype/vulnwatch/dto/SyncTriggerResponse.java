package com.prototype.vulnwatch.dto;

import java.util.UUID;

public record SyncTriggerResponse(
        UUID runId,
        String status,
        String message
) {
}
