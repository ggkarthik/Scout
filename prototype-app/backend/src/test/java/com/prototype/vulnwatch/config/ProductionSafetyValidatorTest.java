package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;

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
                "*");

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
                "https://app.example.com");

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsEnabledTestPersonasForProduction() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                true);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsSuperuserRuntimeRole() {
        JdbcTemplate jdbcTemplate = safeRoleJdbcTemplate();
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(true, false, false);
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                true,
                jdbcTemplate);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsBypassRlsRuntimeRole() {
        JdbcTemplate jdbcTemplate = safeRoleJdbcTemplate();
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(false, true, false);
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                true,
                jdbcTemplate);

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
            String corsAllowedOrigins
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                false);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled
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
                corsAllowedOrigins,
                testPersonasEnabled,
                false,
                safeRoleJdbcTemplate());
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            JdbcTemplate jdbcTemplate
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                false,
                jdbcTemplate);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            boolean validateRlsRuntimeRole,
            JdbcTemplate jdbcTemplate
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
                corsAllowedOrigins,
                testPersonasEnabled,
                validateRlsRuntimeRole,
                jdbcTemplate);
    }

    private JdbcTemplate safeRoleJdbcTemplate() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(false, false, false);
        when(jdbcTemplate.queryForObject(anyString(), eq(String.class))).thenReturn("off");
        return jdbcTemplate;
    }
}
