package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CorporateEmailPolicyTest {

    @Test
    void acceptsValidCorporateDomains() {
        assertTrue(CorporateEmailPolicy.isCorporateEmail("alex@acme-security.com"));
        assertTrue(CorporateEmailPolicy.isCorporateEmail("alex@engineering.example.co.uk"));
    }

    @Test
    void rejectsFreeProvidersAndInvalidDomains() {
        assertFalse(CorporateEmailPolicy.isCorporateEmail("alex@gmail.com"));
        assertFalse(CorporateEmailPolicy.isCorporateEmail("alex@yahoo.co.uk"));
        assertFalse(CorporateEmailPolicy.isCorporateEmail("alex@outlook.com"));
        assertFalse(CorporateEmailPolicy.isCorporateEmail("alex@localhost"));
        assertFalse(CorporateEmailPolicy.isCorporateEmail("alex@invalid_domain.com"));
    }

    @Test
    void throwsAStableApiErrorForNonCorporateEmail() {
        DemoAccessException error = assertThrows(
                DemoAccessException.class,
                () -> CorporateEmailPolicy.requireCorporateEmail("alex@gmail.com"));

        assertEquals("CORPORATE_EMAIL_REQUIRED", error.getCode());
    }
}
