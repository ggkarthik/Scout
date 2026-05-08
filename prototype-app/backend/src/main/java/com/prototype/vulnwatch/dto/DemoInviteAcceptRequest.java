package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DemoInviteAcceptRequest(
        @NotBlank
        @Size(min = 8, max = 200)
        String password
) {
}
