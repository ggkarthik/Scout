package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ProductionSafetyValidatorTest {

    @Test
    void validateAllowsProductionSafeConfiguration() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertDoesNotThrow(validator::validate);
    }

    @Test
    void validateRejectsWildcardCorsOrigins() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "*",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsNonS3ArchiveBackend() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "filesystem",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsApiKeyModeForProduction() {
        ProductionSafetyValidator validator = validator(
                "",
                true,
                "https://issuer.example.com",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsMissingJwtIssuerOrJwk() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsMissingTenantContextRequirement() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                false,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsEnabledTestPersonasForProduction() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456",
                true);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateAllowsStrongHmacSecretWithoutIssuer() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "",
                "",
                "phase-1-validation-auth-secret-32-bytes",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com",
                true,
                "scout@example.com",
                "re_abcdefghijklmnopqrstuvwxyz123456");

        assertDoesNotThrow(validator::validate);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String jwtHmacSecret,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String archiveStorageBackend,
            String archiveS3Bucket,
            String corsAllowedOrigins,
            boolean emailEnabled,
            String emailFrom,
            String resendApiKey
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                jwtHmacSecret,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                archiveStorageBackend,
                archiveS3Bucket,
                corsAllowedOrigins,
                emailEnabled,
                emailFrom,
                resendApiKey,
                false);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String jwtHmacSecret,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String archiveStorageBackend,
            String archiveS3Bucket,
            String corsAllowedOrigins,
            boolean emailEnabled,
            String emailFrom,
            String resendApiKey,
            boolean testPersonasEnabled
    ) {
        return new ProductionSafetyValidator(
                true,
                "",
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                jwtHmacSecret,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                archiveStorageBackend,
                archiveS3Bucket,
                corsAllowedOrigins,
                testPersonasEnabled,
                emailEnabled,
                emailFrom,
                resendApiKey,
                "https://app.example.com");
    }
}
