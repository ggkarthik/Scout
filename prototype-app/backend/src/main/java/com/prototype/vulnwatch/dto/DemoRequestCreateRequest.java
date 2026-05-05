package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record DemoRequestCreateRequest(
        @NotBlank @Size(max = 255) String fullName,
        @NotBlank @Email @Size(max = 255) String email,
        @NotBlank @Size(max = 255) String company,
        @Size(max = 255) String roleTitle,
        @Size(max = 80) String companySize,
        @Size(max = 120) String useCase,
        @Size(max = 2000) String notes,
        @AssertTrue(message = "Demo terms must be accepted") boolean acceptedTerms
) {
}
