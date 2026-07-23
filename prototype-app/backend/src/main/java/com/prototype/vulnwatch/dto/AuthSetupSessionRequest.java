package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthSetupSessionRequest(
        @NotBlank @Size(max = 255) String setupToken
) {
}
