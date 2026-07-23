package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.http.TurnstileClient;
import com.prototype.vulnwatch.client.http.TurnstileClient.VerificationResult;
import java.util.List;
import org.junit.jupiter.api.Test;

class TurnstileVerificationServiceTest {

    @Test
    void acceptsSuccessfulVerificationForExpectedHostnameAndAction() {
        TurnstileClient client = mock(TurnstileClient.class);
        when(client.verify("secret", "valid-token", null)).thenReturn(
                new VerificationResult(true, "scoutgrid.io", "demo_request", List.of()));
        TurnstileVerificationService service = new TurnstileVerificationService(
                client, true, "secret", "scoutgrid.io");

        assertDoesNotThrow(() -> service.verifyDemoRequest("valid-token"));
        verify(client).verify("secret", "valid-token", null);
    }

    @Test
    void rejectsFailedOrContextMismatchedVerification() {
        TurnstileClient client = mock(TurnstileClient.class);
        when(client.verify("secret", "valid-token", null)).thenReturn(
                new VerificationResult(true, "attacker.example", "other_action", List.of()));
        TurnstileVerificationService service = new TurnstileVerificationService(
                client, true, "secret", "scoutgrid.io");

        DemoAccessException error = assertThrows(
                DemoAccessException.class,
                () -> service.verifyDemoRequest("valid-token"));

        assertEquals("CAPTCHA_INVALID", error.getCode());
    }

    @Test
    void rejectsMissingTokenWithoutCallingCloudflare() {
        TurnstileVerificationService service = new TurnstileVerificationService(
                mock(TurnstileClient.class), true, "secret", "scoutgrid.io");

        DemoAccessException error = assertThrows(
                DemoAccessException.class,
                () -> service.verifyDemoRequest(" "));

        assertEquals("CAPTCHA_INVALID", error.getCode());
    }
}
