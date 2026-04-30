package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsCredentialProvider;
import com.prototype.vulnwatch.client.AwsDiscoveryClient;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsConnectivityResult;
import com.prototype.vulnwatch.domain.AwsAuthType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AwsConnectionTestResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
public class AwsDiscoveryConfigService {

    private static final String DEFAULT_RESOURCE_TYPES = "[\"EC2\"]";

    private final AwsDiscoveryConfigRepository repo;
    private final AwsDiscoveryClient awsDiscoveryClient;
    private final ObjectMapper objectMapper;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;

    public AwsDiscoveryConfigService(
            AwsDiscoveryConfigRepository repo,
            AwsDiscoveryClient awsDiscoveryClient,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this.repo = repo;
        this.awsDiscoveryClient = awsDiscoveryClient;
        this.objectMapper = objectMapper;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
    }

    @Transactional(readOnly = true)
    public AwsDiscoveryConfigResponse get(Tenant tenant) {
        AwsDiscoveryConfig config = repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                .orElse(null);
        return toResponse(config);
    }

    @Transactional
    public AwsDiscoveryConfigResponse save(Tenant tenant, AwsDiscoveryConfigRequest request) {
        AwsDiscoveryConfig config = repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                .orElseGet(() -> {
                    tenantQuotaService.assertCanCreateConnector(tenant, "aws");
                    AwsDiscoveryConfig c = new AwsDiscoveryConfig();
                    c.setTenant(tenant);
                    c.setSourceSystem("aws");
                    return c;
                });
        apply(config, request);
        config.touch();
        return toResponse(repo.save(config));
    }

    @Transactional
    public AwsConnectionTestResponse test(Tenant tenant) {
        AwsDiscoveryConfig config = repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST,
                        "AWS Cloud Discovery connector is not configured yet"));

        Instant testedAt = Instant.now();
        AwsCredentialsProvider creds;
        try {
            creds = AwsCredentialProvider.from(configWithDecryptedCredential(config));
        } catch (Exception e) {
            persistTestResult(config, "FAILED", e.getMessage(), testedAt, null);
            return new AwsConnectionTestResponse("FAILED", e.getMessage(), null, Collections.emptyList(), testedAt);
        }

        List<String> regions = parseRegions(config.getRegionsJson());
        AwsConnectivityResult result = awsDiscoveryClient.testConnectivity(creds, regions);

        String status = result.success() ? "SUCCESS" : "FAILED";
        String message = result.success()
                ? "AWS connection succeeded. Account: " + result.accountId()
                + ". Reachable regions: " + String.join(", ", result.reachableRegions()) + "."
                : "AWS connection failed: " + result.errorMessage();

        // Store resolved account ID
        if (result.success() && hasText(result.accountId())) {
            config.setAwsAccountId(result.accountId());
        }
        persistTestResult(config, status, message, testedAt, result.accountId());
        return new AwsConnectionTestResponse(status, message, result.accountId(), result.reachableRegions(), testedAt);
    }

    // ── Private helpers ────────────────────────────────────────────────────────────────────────

    private void apply(AwsDiscoveryConfig config, AwsDiscoveryConfigRequest request) {
        if (request.authType() != null) {
            config.setAuthType(parseAuthType(request.authType()));
        }
        config.setAccessKeyId(trimToNull(request.accessKeyId()));
        if (hasText(request.credentialSecret())) {
            config.setCredentialSecret(credentialEncryptionService.encrypt(request.credentialSecret().trim()));
        }
        config.setCrossAccountRoleArn(trimToNull(request.crossAccountRoleArn()));
        config.setExternalId(trimToNull(request.externalId()));
        if (hasText(request.regionsJson())) {
            config.setRegionsJson(request.regionsJson().trim());
        }
        config.setResourceTypesJson(DEFAULT_RESOURCE_TYPES);
        config.setEnabled(request.enabled() == null || request.enabled());
        config.setAutoSyncEnabled(request.autoSyncEnabled() != null && request.autoSyncEnabled());
        config.setIntervalMinutes(request.intervalMinutes() == null ? 1440
                : Math.max(5, request.intervalMinutes()));
    }

    private void persistTestResult(AwsDiscoveryConfig config, String status, String message,
                                   Instant testedAt, String resolvedAccountId) {
        config.setLastTestStatus(status);
        config.setLastTestMessage(message);
        config.setLastTestedAt(testedAt);
        if (hasText(resolvedAccountId)) {
            config.setAwsAccountId(resolvedAccountId);
        }
        config.touch();
        repo.save(config);
    }

    private AwsDiscoveryConfigResponse toResponse(AwsDiscoveryConfig config) {
        if (config == null) {
            return new AwsDiscoveryConfigResponse(
                    null, "aws", false, AwsAuthType.INSTANCE_METADATA.name(),
                    "", false, "", "", null,
                    "[\"us-east-1\"]",
                    DEFAULT_RESOURCE_TYPES,
                    true, false, 1440,
                    null, null, null, null);
        }
        boolean configured = config.getAuthType() == AwsAuthType.INSTANCE_METADATA
                || (hasText(config.getAccessKeyId()) && hasText(config.getCredentialSecret()))
                || hasText(config.getCrossAccountRoleArn());
        return new AwsDiscoveryConfigResponse(
                config.getId(),
                config.getSourceSystem(),
                configured,
                (config.getAuthType() == null ? AwsAuthType.INSTANCE_METADATA : config.getAuthType()).name(),
                defaultIfBlank(config.getAccessKeyId(), ""),
                hasText(config.getCredentialSecret()),
                defaultIfBlank(config.getCrossAccountRoleArn(), ""),
                defaultIfBlank(config.getExternalId(), ""),
                config.getAwsAccountId(),
                defaultIfBlank(config.getRegionsJson(), "[\"us-east-1\"]"),
                DEFAULT_RESOURCE_TYPES,
                config.isEnabled(),
                config.isAutoSyncEnabled(),
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                config.getLastTestStatus(),
                config.getLastTestMessage(),
                config.getLastTestedAt(),
                config.getLastSyncAt()
        );
    }

    private List<String> parseRegions(String regionsJson) {
        if (!hasText(regionsJson)) return List.of("us-east-1");
        try {
            return objectMapper.readValue(regionsJson, new TypeReference<>() {});
        } catch (Exception e) {
            return List.of("us-east-1");
        }
    }

    private AwsAuthType parseAuthType(String value) {
        try {
            return AwsAuthType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(BAD_REQUEST, "Unsupported AWS auth type: " + value);
        }
    }

    AwsDiscoveryConfig configWithDecryptedCredential(AwsDiscoveryConfig config) {
        if (config == null || !hasText(config.getCredentialSecret())) {
            return config;
        }
        AwsDiscoveryConfig runtimeConfig = new AwsDiscoveryConfig();
        runtimeConfig.setTenant(config.getTenant());
        runtimeConfig.setSourceSystem(config.getSourceSystem());
        runtimeConfig.setAuthType(config.getAuthType());
        runtimeConfig.setAccessKeyId(config.getAccessKeyId());
        runtimeConfig.setCredentialSecret(credentialEncryptionService.decrypt(config.getCredentialSecret()));
        runtimeConfig.setCrossAccountRoleArn(config.getCrossAccountRoleArn());
        runtimeConfig.setExternalId(config.getExternalId());
        runtimeConfig.setAwsAccountId(config.getAwsAccountId());
        runtimeConfig.setRegionsJson(config.getRegionsJson());
        runtimeConfig.setResourceTypesJson(config.getResourceTypesJson());
        runtimeConfig.setEnabled(config.isEnabled());
        runtimeConfig.setAutoSyncEnabled(config.isAutoSyncEnabled());
        runtimeConfig.setIntervalMinutes(config.getIntervalMinutes());
        return runtimeConfig;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String trimToNull(String value) {
        if (value == null) return null;
        String t = value.trim();
        return t.isEmpty() ? null : t;
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }
}
