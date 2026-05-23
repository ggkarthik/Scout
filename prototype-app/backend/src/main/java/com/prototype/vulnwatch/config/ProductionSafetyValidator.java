package com.prototype.vulnwatch.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;

@Component
public class ProductionSafetyValidator {

    private final boolean requireProductionSecrets;
    private final String apiKey;
    private final String creatorKey;
    private final boolean allowApiKeyAuth;
    private final String jwtIssuerUri;
    private final String jwtJwkSetUri;
    private final String credentialEncryptionKey;
    private final boolean allowHeaderTenantSelection;
    private final boolean requireTenantContext;
    private final String corsAllowedOrigins;
    private final boolean testPersonasEnabled;

    public ProductionSafetyValidator(
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.api-key:}") String apiKey,
            @Value("${app.security.creator-key:}") String creatorKey,
            @Value("${app.security.allow-api-key-auth:true}") boolean allowApiKeyAuth,
            @Value("${app.security.jwt.issuer-uri:}") String jwtIssuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwtJwkSetUri,
            @Value("${app.security.credential-encryption-key:}") String credentialEncryptionKey,
            @Value("${app.tenancy.allow-header-tenant-selection:false}") boolean allowHeaderTenantSelection,
            @Value("${app.tenancy.require-tenant-context:true}") boolean requireTenantContext,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins,
            @Value("${app.test-personas.enabled:false}") boolean testPersonasEnabled
    ) {
        this.requireProductionSecrets = requireProductionSecrets;
        this.apiKey = apiKey;
        this.creatorKey = creatorKey;
        this.allowApiKeyAuth = allowApiKeyAuth;
        this.jwtIssuerUri = jwtIssuerUri;
        this.jwtJwkSetUri = jwtJwkSetUri;
        this.credentialEncryptionKey = credentialEncryptionKey;
        this.allowHeaderTenantSelection = allowHeaderTenantSelection;
        this.requireTenantContext = requireTenantContext;
        this.corsAllowedOrigins = corsAllowedOrigins;
        this.testPersonasEnabled = testPersonasEnabled;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void validate() {
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
