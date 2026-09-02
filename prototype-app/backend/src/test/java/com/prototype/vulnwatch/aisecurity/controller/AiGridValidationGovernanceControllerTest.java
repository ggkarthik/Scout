package com.prototype.vulnwatch.aisecurity.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import com.prototype.vulnwatch.aisecurity.service.AiGridPolicyDeprecationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR1CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridR2CertificationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridValidationGovernanceService;
import com.prototype.vulnwatch.service.RequestActorService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AiGridValidationGovernanceControllerTest {
    private final AiGridValidationGovernanceController controller = new AiGridValidationGovernanceController(
            mock(AiGridValidationGovernanceService.class), mock(AiGridPolicyDeprecationService.class),
            mock(AiGridR1CertificationService.class), mock(AiGridR2CertificationService.class),
            mock(RequestActorService.class));

    @Test
    void versionKeyedDigestReadinessAndPublishRoutesReturnTheExplicitMigrationError() {
        assertGone(() -> controller.policyDigest("AGCF-AWS-017", "1.0.0"));
        assertGone(() -> controller.releaseReadiness("AGCF-AWS-017", "1.0.0"));
        assertGone(() -> controller.publish("AGCF-AWS-017", "1.0.0"));
    }

    private void assertGone(Runnable invocation) {
        ResponseStatusException error = assertThrows(ResponseStatusException.class, invocation::run);
        assertEquals(HttpStatus.GONE, error.getStatusCode());
        assertEquals("Version-keyed AI Grid release routes were replaced by policy-ID keyed routes", error.getReason());
    }
}
