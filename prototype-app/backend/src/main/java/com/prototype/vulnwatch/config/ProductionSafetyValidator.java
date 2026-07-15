package com.prototype.vulnwatch.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import java.util.List;
import java.util.Map;

@Component
public class ProductionSafetyValidator {

    private final boolean requireProductionSecrets;
    private final String apiKey;
    private final String creatorKey;
    private final boolean allowApiKeyAuth;
    private final String jwtIssuerUri;
    private final String jwtJwkSetUri;
    private final String jwtHmacSecret;
    private final boolean allowHmacInProduction;
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
            @Value("${app.security.jwt.hmac-secret:}") String jwtHmacSecret,
            @Value("${app.security.jwt.allow-hmac-in-production:false}") boolean allowHmacInProduction,
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
        this.jwtHmacSecret = jwtHmacSecret;
        this.allowHmacInProduction = allowHmacInProduction;
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
            if (validateRlsRuntimeRole) {
                validateRuntimeRoleCannotBypassRls();
            }
            return;
        }
        if (allowApiKeyAuth) {
            throw new IllegalStateException("APP_ALLOW_API_KEY_AUTH must be false for production startup.");
        }
        if (hasText(creatorKey)) {
            throw new IllegalStateException("APP_CREATOR_KEY must be unset for production startup.");
        }
        if (!hasText(jwtIssuerUri) && !hasText(jwtJwkSetUri)) {
            if (!allowHmacInProduction) {
                throw new IllegalStateException(
                        "APP_JWT_ISSUER_URI or APP_JWT_JWK_SET_URI must be set for production startup; "
                                + "preproduction HMAC requires APP_ALLOW_HMAC_IN_PRODUCTION=true."
                );
            }
            if (!hasStrongValue(jwtHmacSecret) || isPlaceholder(jwtHmacSecret)) {
                throw new IllegalStateException(
                        "APP_JWT_HMAC_SECRET must be a non-placeholder value of at least 32 characters when HMAC is enabled."
                );
            }
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
        validateRuntimeRoleCannotBypassRls();
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
                    where (n.nspname = 'platform' or n.nspname = 'tenant_default' or n.nspname ~ '^tenant_')
                      and c.relkind in ('r', 'p')
                      and r.rolname = current_user
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(ownsTenantTables)) {
            throw new IllegalStateException("Production DB runtime role must not own tenant/platform tables protected by RLS.");
        }
        Boolean canCreateInProtectedSchemas = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from pg_namespace n
                    where (n.nspname = 'platform' or n.nspname = 'tenant_default' or n.nspname ~ '^tenant_')
                      and has_schema_privilege(current_user, n.oid, 'CREATE')
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(canCreateInProtectedSchemas)) {
            throw new IllegalStateException("Production DB runtime role must not have CREATE on platform or tenant schemas.");
        }
        Boolean canAssumeUnsafeRole = platformJdbcTemplate.queryForObject("""
                with recursive memberships(roleid) as (
                    select m.roleid
                    from pg_auth_members m
                    join pg_roles me on me.oid = m.member
                    where me.rolname = current_user
                    union
                    select m.roleid
                    from pg_auth_members m
                    join memberships inherited on inherited.roleid = m.member
                )
                select exists (
                    select 1 from memberships m
                    join pg_roles r on r.oid = m.roleid
                    where r.rolsuper or r.rolbypassrls
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(canAssumeUnsafeRole)) {
            throw new IllegalStateException("Production DB runtime role must not inherit or assume a superuser/BYPASSRLS role.");
        }
        Boolean incompleteRls = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from platform.tenants t
                    join pg_namespace n on n.nspname = t.schema_name
                    join pg_class c on c.relnamespace = n.oid and c.relkind in ('r', 'p')
                    where c.relname not in ('tenant_schema_history', 'flyway_schema_history')
                      and (
                          not c.relrowsecurity
                          or not c.relforcerowsecurity
                          or not exists (
                              select 1 from pg_policy p
                              where p.polrelid = c.oid and p.polname = 'tenant_isolation'
                          )
                      )
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(incompleteRls)) {
            throw new IllegalStateException("Production startup rejected: tenant RLS coverage is incomplete.");
        }
        Boolean conflictingRows = platformJdbcTemplate.queryForObject("""
                select exists (
                    select 1
                    from platform.tenants t
                    left join platform.tenant_schema_versions v on v.tenant_id = t.id
                    where t.status = 'ACTIVE'
                      and (v.tenant_id is null or v.status <> 'CURRENT' or v.current_version < 44)
                )
                """, Boolean.class);
        if (Boolean.TRUE.equals(conflictingRows)) {
            throw new IllegalStateException("Production startup rejected: one or more tenant schemas are not current.");
        }
        validateRegisteredTenantRows();
    }

    private void validateRegisteredTenantRows() {
        List<Map<String, Object>> schemas = platformJdbcTemplate.queryForList("""
                select id, schema_name from platform.tenants where status = 'ACTIVE'
                """);
        for (Map<String, Object> tenant : schemas) {
            String schema = String.valueOf(tenant.get("schema_name"));
            String tenantId = String.valueOf(tenant.get("id"));
            List<String> tables = platformJdbcTemplate.queryForList("""
                    select table_name
                    from information_schema.columns
                    where table_schema = ? and column_name = 'tenant_id'
                      and table_name not in ('tenant_schema_history', 'flyway_schema_history')
                    order by table_name
                    """, String.class, schema);
            for (String table : tables) {
                Long conflicts = platformJdbcTemplate.queryForObject(
                        "select count(*) from " + quoteIdentifier(schema) + "." + quoteIdentifier(table)
                                + " where tenant_id is not null and tenant_id <> ?::uuid",
                        Long.class,
                        tenantId);
                if (conflicts != null && conflicts > 0) {
                    throw new IllegalStateException(
                            "Production startup rejected: conflicting tenant rows in " + schema + "." + table);
                }
            }
        }
    }

    private String quoteIdentifier(String identifier) {
        return "\"" + identifier.replace("\"", "\"\"") + "\"";
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
