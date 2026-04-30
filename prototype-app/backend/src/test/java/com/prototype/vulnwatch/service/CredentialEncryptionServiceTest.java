package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class CredentialEncryptionServiceTest {

    private static final String TEST_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    @Test
    void encryptsAndDecryptsCredential() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY);

        String encrypted = service.encrypt("super-secret-token");

        assertTrue(service.isEncrypted(encrypted));
        assertNotEquals("super-secret-token", encrypted);
        assertEquals("super-secret-token", service.decrypt(encrypted));
    }

    @Test
    void encryptionIsNonDeterministic() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY);

        assertNotEquals(service.encrypt("same-secret"), service.encrypt("same-secret"));
    }

    @Test
    void decryptReturnsLegacyPlaintextForMigrationCompatibility() {
        CredentialEncryptionService service = new CredentialEncryptionService(TEST_KEY);

        assertFalse(service.isEncrypted("legacy-secret"));
        assertEquals("legacy-secret", service.decrypt("legacy-secret"));
    }

    @Test
    void rejectsNon256BitKey() {
        assertThrows(IllegalStateException.class, () -> new CredentialEncryptionService("AAAA"));
    }
}
