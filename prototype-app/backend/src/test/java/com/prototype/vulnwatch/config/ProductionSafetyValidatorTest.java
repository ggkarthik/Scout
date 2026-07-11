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
                "https://app.example.com",
                disabledBootstrap());

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
                "*",
                disabledBootstrap());

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
                "https://app.example.com",
                disabledBootstrap());

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
                "https://app.example.com",
                disabledBootstrap());

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
                "https://app.example.com",
                disabledBootstrap());

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
                true,
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsEnabledPlatformOwnerBootstrapWithoutUsers() {
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
                enabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsLegacyPlatformOwnerCredentialProperties() {
        ProductionSafetyValidator validator = validator(
                "",
                false,
                "https://issuer.example.com",
                "",
                "legacy.owner@example.com",
                "$2a$10$legacyhashlegacyhashlegacyhashlegacyhashlegacyhash12",
                "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
                false,
                true,
                "https://app.example.com",
                false,
                false,
                safeRoleJdbcTemplate(),
                disabledBootstrap());

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsProductionBootstrapUsersWithoutEmail() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed = new PlatformOwnerBootstrapProperties.PlatformOwnerSeed();
        seed.setExternalSubject("owner-subject");
        properties.setUsers(java.util.List.of(seed));

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
                properties);

        assertThrows(IllegalStateException.class, validator::validate);
    }

    @Test
    void validateRejectsProductionBootstrapUsersWithLocalhostEmail() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed = new PlatformOwnerBootstrapProperties.PlatformOwnerSeed();
        seed.setEmail("platform.owner@localhost");
        properties.setUsers(java.util.List.of(seed));

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
                properties);

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
                jdbcTemplate,
                disabledBootstrap());

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
                jdbcTemplate,
                disabledBootstrap());

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
            String corsAllowedOrigins,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
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
                false,
                platformOwnerBootstrapProperties);
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
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return new ProductionSafetyValidator(
                true,
                "",
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                "",
                "",
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                false,
                safeRoleJdbcTemplate(),
                platformOwnerBootstrapProperties);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String legacyPlatformOwnerEmail,
            String legacyPlatformOwnerPasswordHash,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            JdbcTemplate jdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                legacyPlatformOwnerEmail,
                legacyPlatformOwnerPasswordHash,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                false,
                jdbcTemplate,
                platformOwnerBootstrapProperties);
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
            JdbcTemplate jdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return validator(
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                "",
                "",
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                validateRlsRuntimeRole,
                jdbcTemplate,
                platformOwnerBootstrapProperties);
    }

    private ProductionSafetyValidator validator(
            String creatorKey,
            boolean allowApiKeyAuth,
            String jwtIssuerUri,
            String jwtJwkSetUri,
            String legacyPlatformOwnerEmail,
            String legacyPlatformOwnerPasswordHash,
            String credentialEncryptionKey,
            boolean allowHeaderTenantSelection,
            boolean requireTenantContext,
            String corsAllowedOrigins,
            boolean testPersonasEnabled,
            boolean validateRlsRuntimeRole,
            JdbcTemplate jdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        return new ProductionSafetyValidator(
                true,
                "",
                creatorKey,
                allowApiKeyAuth,
                jwtIssuerUri,
                jwtJwkSetUri,
                legacyPlatformOwnerEmail,
                legacyPlatformOwnerPasswordHash,
                credentialEncryptionKey,
                allowHeaderTenantSelection,
                requireTenantContext,
                corsAllowedOrigins,
                testPersonasEnabled,
                validateRlsRuntimeRole,
                jdbcTemplate,
                platformOwnerBootstrapProperties);
    }

    private PlatformOwnerBootstrapProperties disabledBootstrap() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(false);
        return properties;
    }

    private PlatformOwnerBootstrapProperties enabledBootstrap() {
        PlatformOwnerBootstrapProperties properties = new PlatformOwnerBootstrapProperties();
        properties.setEnabled(true);
        return properties;
    }

    private JdbcTemplate safeRoleJdbcTemplate() {
        JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);
        when(jdbcTemplate.queryForObject(anyString(), eq(Boolean.class)))
                .thenReturn(false, false, false);
        when(jdbcTemplate.queryForObject(anyString(), eq(String.class))).thenReturn("off");
        return jdbcTemplate;
    }
}
