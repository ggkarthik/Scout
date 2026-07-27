package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.CredentialEncryptionService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.auth.StsAssumeRoleCredentialsProvider;
import software.amazon.awssdk.services.sts.model.AssumeRoleRequest;

@Service
public class AiSecurityAwsConnectorService {

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final CredentialEncryptionService encryptionService;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final IngestionJobService ingestionJobService;

    public AiSecurityAwsConnectorService(
            NamedParameterJdbcTemplate jdbc,
            ObjectMapper objectMapper,
            CredentialEncryptionService encryptionService,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            IngestionJobService ingestionJobService
    ) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.encryptionService = encryptionService;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.ingestionJobService = ingestionJobService;
    }

    public ConnectorConfigResponse get(Tenant tenant) {
        return tenantExecution.run(tenant, () -> rows().stream().findFirst().orElse(null));
    }

    public ConnectorConfigResponse save(Tenant tenant, ConnectorConfigRequest request) {
        validate(request);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            UUID id = rows().stream().findFirst().map(ConnectorConfigResponse::id).orElse(UUID.randomUUID());
            jdbc.update("""
                    insert into ai_security_connector_configs as existing (
                        id, tenant_id, provider, account_id, role_arn, external_id_ciphertext,
                        regions_json, enabled
                    ) values (
                        :id, :tenantId, 'AWS', :accountId, :roleArn, :externalId,
                        cast(:regions as jsonb), :enabled
                    ) on conflict (id) do update
                        set account_id = excluded.account_id,
                            role_arn = excluded.role_arn,
                            external_id_ciphertext = coalesce(
                                excluded.external_id_ciphertext,
                                existing.external_id_ciphertext
                            ),
                            regions_json = excluded.regions_json,
                            enabled = excluded.enabled,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("id", id)
                    .addValue("tenantId", tenant.getId())
                    .addValue("accountId", request.accountId().trim())
                    .addValue("roleArn", blankToNull(request.roleArn()))
                    .addValue("externalId", encryptionService.encrypt(blankToNull(request.externalId())))
                    .addValue("regions", json(request.regions()))
                    .addValue("enabled", request.enabled()));
            return rows().stream().filter(row -> row.accountId().equals(request.accountId().trim())).findFirst()
                    .orElseThrow();
        }));
    }

    public ConnectionTestResponse test(Tenant tenant) {
        ConnectorSecret config = secret(tenant);
        try (CredentialsHandle handle = credentials(config);
             StsClient sts = StsClient.builder()
                     .region(Region.US_EAST_1)
                     .credentialsProvider(handle.provider())
                     .build()) {
            String actualAccount = sts.getCallerIdentity().account();
            if (!config.accountId().equals(actualAccount)) {
                return new ConnectionTestResponse(false, "INVALID_CONFIGURATION",
                        "The assumed identity belongs to a different AWS account", false, List.of());
            }
            return new ConnectionTestResponse(true, null, "AWS connection successful", false, List.of());
        } catch (software.amazon.awssdk.services.sts.model.StsException ex) {
            String code = ex.awsErrorDetails() == null ? "ASSUME_ROLE_FAILED" : ex.awsErrorDetails().errorCode();
            return new ConnectionTestResponse(false, normalizeStsCode(code),
                    "Unable to assume the configured AWS role", false, List.of("sts:AssumeRole"));
        } catch (Exception ex) {
            return new ConnectionTestResponse(false, "PROVIDER_UNAVAILABLE",
                    "AWS connection test could not be completed", true, List.of());
        }
    }

    public IngestionJobAcceptedResponse trigger(Tenant tenant, String requestedBy) {
        ConnectorSecret config = secret(tenant);
        if (!config.enabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "AI Security connector is disabled");
        }
        return ingestionJobService.enqueueAiSecurityJob(tenant, config.id(), requestedBy);
    }

    public ConnectorSecret secret(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id, account_id, role_arn, external_id_ciphertext, regions_json::text, enabled
                  from ai_security_connector_configs
                 where provider = 'AWS'
                 order by updated_at desc limit 1
                """, rs -> {
            if (!rs.next()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security AWS connector is not configured");
            }
            return new ConnectorSecret(
                    rs.getObject("id", UUID.class),
                    rs.getString("account_id"),
                    rs.getString("role_arn"),
                    encryptionService.decrypt(rs.getString("external_id_ciphertext")),
                    readRegions(rs.getString("regions_json")),
                    rs.getBoolean("enabled"));
        }));
    }

    public CredentialsHandle credentials(ConnectorSecret config) {
        AwsCredentialsProvider base = DefaultCredentialsProvider.create();
        if (config.roleArn() == null || config.roleArn().isBlank()) {
            return new CredentialsHandle(base, null);
        }
        StsClient sts = StsClient.builder()
                .region(Region.US_EAST_1)
                .credentialsProvider(base)
                .build();
        AssumeRoleRequest.Builder request = AssumeRoleRequest.builder()
                .roleArn(config.roleArn())
                .roleSessionName("scout-ai-security-" + config.accountId());
        if (config.externalId() != null && !config.externalId().isBlank()) {
            request.externalId(config.externalId());
        }
        StsAssumeRoleCredentialsProvider assumed = StsAssumeRoleCredentialsProvider.builder()
                .stsClient(sts)
                .refreshRequest(request.build())
                .build();
        return new CredentialsHandle(assumed, sts);
    }

    private List<ConnectorConfigResponse> rows() {
        return jdbc.query("""
                select id, account_id, role_arn, regions_json::text, enabled, created_at, updated_at
                  from ai_security_connector_configs
                 where provider = 'AWS' order by updated_at desc
                """, (rs, rowNum) -> new ConnectorConfigResponse(
                rs.getObject("id", UUID.class),
                rs.getString("account_id"),
                rs.getString("role_arn"),
                rs.getString("role_arn") == null ? "WORKLOAD_IDENTITY" : "CROSS_ACCOUNT_ROLE",
                readRegions(rs.getString("regions_json")),
                rs.getBoolean("enabled"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant()));
    }

    private void validate(ConnectorConfigRequest request) {
        if (request == null || request.accountId() == null || !request.accountId().matches("\\d{12}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A 12-digit AWS account ID is required");
        }
        if (request.regions() == null || request.regions().isEmpty() || request.regions().size() > 20) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one AWS region is required");
        }
        if (request.roleArn() != null && !request.roleArn().isBlank()
                && !request.roleArn().matches("arn:aws[a-z-]*:iam::\\d{12}:role/.+")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A valid cross-account role ARN is required");
        }
        if (request.roleArn() != null && !request.roleArn().isBlank()
                && !request.roleArn().contains("::" + request.accountId() + ":role/")) {
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "The cross-account role ARN must belong to the configured AWS account"
            );
        }
        if (request.regions().stream().anyMatch(region ->
                region == null || !region.matches("[a-z]{2}(?:-gov)?-[a-z]+-\\d"))) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "One or more AWS regions are invalid");
        }
    }

    private List<String> readRegions(String json) {
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception ex) {
            return List.of();
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to serialize AWS connector regions", ex);
        }
    }

    private String normalizeStsCode(String code) {
        if ("AccessDenied".equalsIgnoreCase(code)) {
            return "ACCESS_DENIED";
        }
        if ("InvalidClientTokenId".equalsIgnoreCase(code)) {
            return "EXTERNAL_ID_MISMATCH";
        }
        return "ASSUME_ROLE_FAILED";
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    public record ConnectorConfigRequest(
            String accountId,
            String roleArn,
            String externalId,
            List<String> regions,
            boolean enabled
    ) {
    }

    public record ConnectorConfigResponse(
            UUID id,
            String accountId,
            String roleArn,
            String authMode,
            List<String> regions,
            boolean enabled,
            java.time.Instant createdAt,
            java.time.Instant updatedAt
    ) {
    }

    public record ConnectionTestResponse(
            boolean success,
            String code,
            String message,
            boolean retryable,
            List<String> missingPermissions
    ) {
    }

    public record ConnectorSecret(
            UUID id,
            String accountId,
            String roleArn,
            String externalId,
            List<String> regions,
            boolean enabled
    ) {
    }

    public static final class CredentialsHandle implements AutoCloseable {
        private final AwsCredentialsProvider provider;
        private final StsClient stsClient;

        CredentialsHandle(AwsCredentialsProvider provider, StsClient stsClient) {
            this.provider = provider;
            this.stsClient = stsClient;
        }

        public AwsCredentialsProvider provider() {
            return provider;
        }

        @Override
        public void close() {
            if (provider instanceof AutoCloseable closeable) {
                try {
                    closeable.close();
                } catch (Exception ignored) {
                    // Nothing actionable remains after the scan.
                }
            }
            if (stsClient != null) {
                stsClient.close();
            }
        }
    }
}
