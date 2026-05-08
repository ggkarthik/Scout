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
    private final String jwtHmacSecret;
    private final String credentialEncryptionKey;
    private final boolean allowHeaderTenantSelection;
    private final boolean requireTenantContext;
    private final String archiveStorageBackend;
    private final String archiveS3Bucket;
    private final String corsAllowedOrigins;
    private final boolean testPersonasEnabled;
    private final boolean emailEnabled;
    private final String emailFrom;
    private final String resendApiKey;
    private final String publicBaseUrl;

    public ProductionSafetyValidator(
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.api-key:}") String apiKey,
            @Value("${app.security.creator-key:}") String creatorKey,
            @Value("${app.security.allow-api-key-auth:true}") boolean allowApiKeyAuth,
            @Value("${app.security.jwt.issuer-uri:}") String jwtIssuerUri,
            @Value("${app.security.jwt.jwk-set-uri:}") String jwtJwkSetUri,
            @Value("${app.security.jwt.hmac-secret:}") String jwtHmacSecret,
            @Value("${app.security.credential-encryption-key:}") String credentialEncryptionKey,
            @Value("${app.tenancy.allow-header-tenant-selection:true}") boolean allowHeaderTenantSelection,
            @Value("${app.tenancy.require-tenant-context:false}") boolean requireTenantContext,
            @Value("${app.archive.storage-backend:filesystem}") String archiveStorageBackend,
            @Value("${app.archive.s3-bucket:}") String archiveS3Bucket,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins,
            @Value("${app.test-personas.enabled:false}") boolean testPersonasEnabled,
            @Value("${app.email.enabled:false}") boolean emailEnabled,
            @Value("${app.email.from:}") String emailFrom,
            @Value("${app.email.resend.api-key:}") String resendApiKey,
            @Value("${app.public.base-url:}") String publicBaseUrl
    ) {
        this.requireProductionSecrets = requireProductionSecrets;
        this.apiKey = apiKey;
        this.creatorKey = creatorKey;
        this.allowApiKeyAuth = allowApiKeyAuth;
        this.jwtIssuerUri = jwtIssuerUri;
        this.jwtJwkSetUri = jwtJwkSetUri;
        this.jwtHmacSecret = jwtHmacSecret;
        this.credentialEncryptionKey = credentialEncryptionKey;
        this.allowHeaderTenantSelection = allowHeaderTenantSelection;
        this.requireTenantContext = requireTenantContext;
        this.archiveStorageBackend = archiveStorageBackend;
        this.archiveS3Bucket = archiveS3Bucket;
        this.corsAllowedOrigins = corsAllowedOrigins;
        this.testPersonasEnabled = testPersonasEnabled;
        this.emailEnabled = emailEnabled;
        this.emailFrom = emailFrom;
        this.resendApiKey = resendApiKey;
        this.publicBaseUrl = publicBaseUrl;
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
        if (!hasText(jwtIssuerUri) && !hasText(jwtJwkSetUri) && !hasText(jwtHmacSecret)) {
            throw new IllegalStateException("APP_JWT_ISSUER_URI, APP_JWT_JWK_SET_URI, or APP_JWT_HMAC_SECRET must be set for production startup.");
        }
        if (hasText(jwtHmacSecret) && !hasStrongValue(jwtHmacSecret)) {
            throw new IllegalStateException("APP_JWT_HMAC_SECRET must be set to a non-default strong secret for production startup.");
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
        if (!"s3".equalsIgnoreCase(archiveStorageBackend)) {
            throw new IllegalStateException("ARCHIVE_STORAGE_BACKEND must be set to s3 for production startup.");
        }
        if (archiveS3Bucket == null || archiveS3Bucket.isBlank() || isPlaceholder(archiveS3Bucket)) {
            throw new IllegalStateException("ARCHIVE_S3_BUCKET must be set to the production vulnerability archive bucket.");
        }
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank() || corsAllowedOrigins.contains("*")) {
            throw new IllegalStateException("APP_CORS_ALLOWED_ORIGINS must be set to explicit production origins.");
        }
        if (testPersonasEnabled) {
            throw new IllegalStateException("APP_TEST_PERSONAS_ENABLED must be false for production startup.");
        }
        if (!emailEnabled) {
            throw new IllegalStateException("APP_EMAIL_ENABLED must be true for production startup.");
        }
        if (!hasText(emailFrom)) {
            throw new IllegalStateException("APP_EMAIL_FROM must be set for production startup.");
        }
        if (!hasStrongValue(resendApiKey)) {
            throw new IllegalStateException("RESEND_API_KEY must be set for production startup.");
        }
        if (!hasText(publicBaseUrl) || isPlaceholder(publicBaseUrl)) {
            throw new IllegalStateException("APP_BASE_URL must be set to the hosted frontend URL for production startup.");
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
