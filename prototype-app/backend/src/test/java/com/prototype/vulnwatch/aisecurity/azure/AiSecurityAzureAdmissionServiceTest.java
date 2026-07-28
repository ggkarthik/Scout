package com.prototype.vulnwatch.aisecurity.azure;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class AiSecurityAzureAdmissionServiceTest {

    @Test
    void enforcesGlobalAndPerSubscriptionBudgets() {
        AiSecurityAzureAdmissionService service = new AiSecurityAzureAdmissionService(2, 1, 1);
        try (var first = service.acquire("subscription-a")) {
            assertThrows(
                    AiSecurityAzureAdmissionService.AdmissionException.class,
                    () -> service.acquire("subscription-a"));
            assertDoesNotThrow(() -> {
                try (var ignored = service.acquire("subscription-b")) {
                    // A different subscription can use the remaining global permit.
                }
            });
        }
        assertDoesNotThrow(() -> {
            try (var ignored = service.acquire("subscription-a")) {
                // The permit is reusable after close.
            }
        });
    }

    @Test
    void rejectsMissingSubscriptionBeforeAllocatingPermits() {
        AiSecurityAzureAdmissionService service = new AiSecurityAzureAdmissionService(1, 1, 1);
        assertThrows(AiSecurityAzureAdmissionService.AdmissionException.class, () -> service.acquire(" "));
        assertDoesNotThrow(() -> {
            try (var ignored = service.acquire("subscription-a")) {
                // Invalid input did not consume capacity.
            }
        });
    }
}
