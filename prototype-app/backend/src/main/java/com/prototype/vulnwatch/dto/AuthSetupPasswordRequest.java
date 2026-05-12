package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record AuthSetupPasswordRequest(
        @NotBlank String setupToken,
        @NotBlank @Size(min = 8, max = 255) String password
) {
}
