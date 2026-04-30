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
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com");

        assertDoesNotThrow(validator::validate);
    }

    @Test
    void validateRejectsWildcardCorsOrigins() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "*");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsNonS3ArchiveBackend() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "filesystem",
                "vulnwatch-prod-archive",
                "https://app.example.com");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsApiKeyModeForProduction() {
        ProductionSafetyValidator validator = validator(
                "",
                true,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsMissingJwtIssuerOrJwk() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsMissingTenantContextRequirement() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                false,
                "s3",
                "vulnwatch-prod-archive",
                "https://app.example.com");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String archiveStorageBackend,
            String archiveS3Bucket,
            String corsAllowedOrigins
    ) {
        return new ProductionSafetyValidator(
                true,
                "",
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                archiveStorageBackend,
                archiveS3Bucket,
                corsAllowedOrigins);
    }
}
