package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.prototype.vulnwatch.aisecurity.aws.AiSecurityAwsAdmissionService;
import org.junit.jupiter.api.Test;

class AiSecurityAwsAdmissionServiceTest {

    @Test
    void serializesTheSameAccountRegionAndReleasesItsBudget() {
        AiSecurityAwsAdmissionService service = new AiSecurityAwsAdmissionService(2, 1);

        try (var ignored = service.acquire("123456789012", "us-east-1")) {
            assertThrows(
                    AiSecurityAwsAdmissionService.AdmissionException.class,
                    () -> service.acquire("123456789012", "us-east-1"));
            assertDoesNotThrow(() -> {
                try (var otherRegion = service.acquire("123456789012", "us-west-2")) {
                    // A separate target can use the remaining global slot.
                }
            });
        }

        assertDoesNotThrow(() -> {
            try (var reacquired = service.acquire("123456789012", "us-east-1")) {
                // Released permits are reusable by the next fair waiter.
            }
        });
    }
}
