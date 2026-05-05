package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.Size;

public record DemoRequestDecisionRequest(
        @Size(max = 255) String reason
) {
}
