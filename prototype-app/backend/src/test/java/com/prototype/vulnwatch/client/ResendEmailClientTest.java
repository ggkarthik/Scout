package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class ResendEmailClientTest {

    @Test
    void fallsBackToVerifiedDomainSenderWhenConfiguredFromDomainDoesNotMatch() {
        ResendEmailClient client = new ResendEmailClient(
                new ObjectMapper(),
                "https://api.resend.com",
                "resend-key",
                "Scout.ai <noreply@wrong-domain.example>",
                "hossstore.in"
        );

        assertEquals(
                "Scout.ai <noreply@hossstore.in>",
                ReflectionTestUtils.getField(client, "fromAddress")
        );
    }

    @Test
    void preservesConfiguredSenderWhenItMatchesVerifiedDomain() {
        ResendEmailClient client = new ResendEmailClient(
                new ObjectMapper(),
                "https://api.resend.com",
                "resend-key",
                "Scout.ai <noreply@hossstore.in>",
                "hossstore.in"
        );

        assertEquals(
                "Scout.ai <noreply@hossstore.in>",
                ReflectionTestUtils.getField(client, "fromAddress")
        );
    }
}
