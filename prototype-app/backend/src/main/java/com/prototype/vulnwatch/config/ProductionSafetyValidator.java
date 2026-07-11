package com.prototype.vulnwatch.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

@Component
public class ProductionSafetyValidator {

    private final boolean requireProductionSecrets;
    private final String apiKey;
    private final String creatorKey;
    private final boolean allowApiKeyAuth;
    private final String jwtIssuerUri;
    private final String jwtJwkSetUri;
    private final String legacyPlatformOwnerEmail;
    private final String legacyPlatformOwnerPasswordHash;
    private final String credentialEncryptionKey;
    private final boolean allowHeaderTenantSelection;
    private final boolean requireTenantContext;
    private final String corsAllowedOrigins;
    private final boolean testPersonasEnabled;
    private final JdbcTemplate platformJdbcTemplate;
    private final boolean validateRlsRuntimeRole;
    private final PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties;

    public ProductionSafetyValidator(
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.api-key:}") String apiKey,
            @Value("${app.security.creator-key:}") String creatorKey,
            @Value("${app.security.allow-api-key-auth:true}") boolean allowApiKeyAuth,
            @Value("${app.security.jwt.issuer-uri:}") String jwtIssuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwtJwkSetUri,
            @Value("${app.security.platform-owner-email:}") String legacyPlatformOwnerEmail,
            @Value("${app.security.platform-owner-password-hash:}") String legacyPlatformOwnerPasswordHash,
            @Value("${app.security.credential-encryption-key:}") String credentialEncryptionKey,
            @Value("${app.tenancy.allow-header-tenant-selection:false}") boolean allowHeaderTenantSelection,
            @Value("${app.tenancy.require-tenant-context:true}") boolean requireTenantContext,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins,
            @Value("${app.test-personas.enabled:false}") boolean testPersonasEnabled,
            @Value("${app.security.validate-rls-runtime-role:false}") boolean validateRlsRuntimeRole,
            @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate,
            PlatformOwnerBootstrapProperties platformOwnerBootstrapProperties
    ) {
        this.requireProductionSecrets = requireProductionSecrets;
        this.apiKey = apiKey;
        this.creatorKey = creatorKey;
        this.allowApiKeyAuth = allowApiKeyAuth;
        this.jwtIssuerUri = jwtIssuerUri;
        this.jwtJwkSetUri = jwtJwkSetUri;
        this.legacyPlatformOwnerEmail = legacyPlatformOwnerEmail;
        this.legacyPlatformOwnerPasswordHash = legacyPlatformOwnerPasswordHash;
        this.credentialEncryptionKey = credentialEncryptionKey;
        this.allowHeaderTenantSelection = allowHeaderTenantSelection;
        this.requireTenantContext = requireTenantContext;
        this.corsAllowedOrigins = corsAllowedOrigins;
        this.testPersonasEnabled = testPersonasEnabled;
        this.platformJdbcTemplate = platformJdbcTemplate;
        this.validateRlsRuntimeRole = validateRlsRuntimeRole;
        this.platformOwnerBootstrapProperties = platformOwnerBootstrapProperties;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void validate() {
        validateLegacyPlatformOwnerCredentialsAreUnused();
        validatePlatformOwnerBootstrapConfiguration();
        if (!requireProductionSecrets) {
            return;
        }
        if (allowApiKeyAuth) {
            throw new IllegalStateException("APP_ALLOW_API_KEY_AUTH must be false for production startup.");
        }
        if (hasText(creatorKey)) {
            throw new IllegalStateException("APP_CREATOR_KEY must be unset for production startup.");
        }
        if (!hasText(jwtIssuerUri) && !hasText(jwtJwkSetUri)) {
            throw new IllegalStateException("APP_JWT_ISSUER_URI or APP_JWT_JWK_SET_URI must be set for production startup.");
        }
        if (allowHeaderTenantSelection) {
            throw new IllegalStateException("APP_ALLOW_HEADER_TENANT_SELECTION must be false for production startup.");
        }
        if (!requireTenantContext) {
            throw new IllegalStateException("APP_REQUIRE_TENANT_CONTEXT must be true for production startup.");
        }
        if (!hasStrongValue(credentialEncryptionKey) || isPlaceholder(credentialEncryptionKey)
                || "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".equals(credentialEncryptionKey)) {
            throw new IllegalStateException("APP_CREDENTIAL_ENCRYPTION_KEY must be set to a non-default 256-bit base64 key for production startup.");
        }
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank() || corsAllowedOrigins.contains("*")) {
            throw new IllegalStateException("APP_CORS_ALLOWED_ORIGINS must be set to explicit production origins.");
        }
        if (testPersonasEnabled) {
            throw new IllegalStateException("APP_TEST_PERSONAS_ENABLED must be false for production startup.");
        }
        if (validateRlsRuntimeRole) {
            validateRuntimeRoleCannotBypassRls();
        }
    }

    private void validatePlatformOwnerBootstrapConfiguration() {
        if (platformOwnerBootstrapProperties == null || !platformOwnerBootstrapProperties.isEnabled()) {
            return;
        }
        if (platformOwnerBootstrapProperties.getUsers() == null || platformOwnerBootstrapProperties.getUsers().isEmpty()) {
            throw new IllegalStateException("APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED is true but no platform owner bootstrap users are configured.");
        }
        for (PlatformOwnerBootstrapProperties.PlatformOwnerSeed seed : platformOwnerBootstrapProperties.getUsers()) {
            boolean hasSubject = hasText(seed.getExternalSubject());
            boolean hasEmail = hasText(seed.getEmail());
            if (!hasSubject && !hasEmail) {
                throw new IllegalStateException("Each platform owner bootstrap user must include externalSubject or email.");
            }
            if (requireProductionSecrets) {
                if (!hasEmail) {
                    throw new IllegalStateException("Production platform owner bootstrap users must include email for password setup and login.");
                }
                String email = seed.getEmail().trim().toLowerCase();
                if (email.endsWith("@localhost")) {
                    throw new IllegalStateException("Production platform owner bootstrap users cannot use localhost email addresses.");
                }
            }
        }
    }

    private void validateLegacyPlatformOwnerCredentialsAreUnused() {
        if (hasText(legacyPlatformOwnerEmail) || hasText(legacyPlatformOwnerPasswordHash)) {
            throw new IllegalStateException(
                    "Legacy platform-owner credential properties are no longer supported. "
                            + "Remove APP_PLATFORM_OWNER_EMAIL / APP_PLATFORM_OWNER_PASSWORD_HASH and use "
                            + "platform-owner bootstrap users plus password setup instead.");
        }
    }

    private void validateRuntimeRoleCannotBypassRls() {
        if (platformJdbcTemplate == null) {
            throw new IllegalStateException("platformJdbcTemplate is required for production DB role safety validation.");
        }
        Boolean superuser = platformJdbcTemplate.queryForObject("""
                select rolsuper
                from pg_roles
                where rolname = current_user
                """, Boolean.class);
        if (Boolean.TRUE.equals(superuser)) {
            throw new IllegalStateException("Production DB runtime role must not be a PostgreSQL superuser; superusers bypass RLS.");
        }
        Boolean bypassRls = platformJdbcTemplate.queryForObject("""
                select rolbypassrls
                from pg_roles
                where rolname = current_user
                """, Boolean.class);
        if (Boolean.TRUE.equals(bypassRls)) {
            throw new IllegalStateException("Production DB runtime role must not have BYPASSRLS.");
        }
        String isSuperuser = platformJdbcTemplate.queryForObject("select current_setting('is_superuser')", String.class);
        if ("on".equalsIgnoreCase(isSuperuser) || "true".equalsIgnoreCase(isSuperuser)) {
            throw new IllegalStateException("Production DB runtime role reports is_superuser=true; RLS would be bypassed.");
        }
        Boolean ownsTenantTables = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    join pg_roles r on r.oid = c.relowner
                    where n.nspname in ('tenant_default', 'platform')
                      and c.relkind in ('r', 'p')
                      and r.rolname = current_user
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(ownsTenantTables)) {
            throw new IllegalStateException("Production DB runtime role must not own tenant/platform tables protected by RLS.");
        }
    }

    private boolean hasStrongValue(String value) {
        return value != null && value.trim().length() >= 24;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean isPlaceholder(String value) {
        return value != null && value.toLowerCase().contains("replace-with");
    }
}
