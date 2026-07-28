package com.prototype.vulnwatch.aisecurity.azure;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService.CredentialTestResponse;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.AzureConnectorTargetFacade;
import com.prototype.vulnwatch.service.AzureConnectorTargetFacade.TargetSnapshot;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiSecurityAzureConnectorService {

    public static final Set<String> RESOURCE_FAMILIES = Set.of(
            "AZURE_AI_ACCOUNTS",
            "AZURE_FOUNDRY_PROJECTS",
            "AZURE_FOUNDRY_DEPLOYMENTS",
            "AZURE_FOUNDRY_AGENTS",
            "AZURE_FOUNDRY_AGENT_TOOLS",
            "AZURE_ML_WORKSPACES",
            "AZURE_ML_MODELS",
            "AZURE_ML_ENDPOINTS",
            "AZURE_ML_DEPLOYMENTS",
            "AZURE_ML_COMPUTE",
            "AZURE_ML_JOBS",
            "AZURE_ML_PIPELINES",
            "AZURE_SEARCH_SERVICES",
            "AZURE_SEARCH_INDEXES",
            "AZURE_SEARCH_SKILLSETS",
            "AZURE_SEARCH_INDEXERS",
            "AZURE_SEARCH_DATA_SOURCES",
            "AZURE_BOT_SERVICES",
            "AZURE_BOT_CHANNELS",
            "AZURE_BOT_IDENTITIES",
            "AZURE_DIAGNOSTIC_SETTINGS",
            "AZURE_RBAC_GLOBAL");

    private static final List<String> DEFAULT_FAMILIES = List.of(
            "AZURE_AI_ACCOUNTS",
            "AZURE_FOUNDRY_PROJECTS",
            "AZURE_FOUNDRY_DEPLOYMENTS",
            "AZURE_ML_WORKSPACES",
            "AZURE_ML_MODELS",
            "AZURE_ML_ENDPOINTS",
            "AZURE_ML_DEPLOYMENTS",
            "AZURE_ML_COMPUTE",
            "AZURE_ML_JOBS",
            "AZURE_ML_PIPELINES",
            "AZURE_SEARCH_SERVICES",
            "AZURE_BOT_SERVICES",
            "AZURE_BOT_CHANNELS",
            "AZURE_BOT_IDENTITIES",
            "AZURE_DIAGNOSTIC_SETTINGS",
            "AZURE_RBAC_GLOBAL");

    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final ObjectMapper objectMapper;
    private final AzureConnectorTargetFacade targets;
    private final AiSecurityAzureCredentialService credentials;
    private final AzureAiManagementClient azure;
    private final AzurePolicyPermissionMatrix permissionMatrix;
    private final IngestionJobService jobs;

    public AiSecurityAzureConnectorService(
            NamedParameterJdbcTemplate jdbc,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            ObjectMapper objectMapper,
            AzureConnectorTargetFacade targets,
            AiSecurityAzureCredentialService credentials,
            AzureAiManagementClient azure,
            AzurePolicyPermissionMatrix permissionMatrix,
            IngestionJobService jobs
    ) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.objectMapper = objectMapper;
        this.targets = targets;
        this.credentials = credentials;
        this.azure = azure;
        this.permissionMatrix = permissionMatrix;
        this.jobs = jobs;
    }

    public List<ConnectorResponse> list(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id, account_id, provider_tenant_id, credential_profile_id,
                       source_config_id, source_target_id, regions_json::text,
                       resource_families_json::text, enabled, created_at, updated_at
                  from ai_security_connector_configs
                 where provider = 'AZURE'
                 order by account_id, id
                """, (rs, rowNum) -> new ConnectorResponse(
                rs.getObject("id", UUID.class),
                rs.getString("account_id"),
                rs.getString("provider_tenant_id"),
                rs.getObject("credential_profile_id", UUID.class),
                rs.getObject("source_config_id", UUID.class),
                rs.getObject("source_target_id", UUID.class),
                readList(rs.getString("regions_json")),
                readList(rs.getString("resource_families_json")),
                rs.getBoolean("enabled"),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant())));
    }

    public ConnectorResponse save(Tenant tenant, ConnectorRequest request) {
        if (request == null || request.credentialProfileId() == null || request.targetId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential profile and Azure target are required");
        }
        var profile = credentials.secret(tenant, request.credentialProfileId());
        TargetSnapshot target = targets.require(tenant, request.targetId());
        if (!target.enabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "The selected Azure target is disabled");
        }
        List<String> families = validateFamilies(request.resourceFamilies());
        List<String> regions = readList(target.regionsJson());
        UUID id = tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            UUID existing = jdbc.query("""
                    select id from ai_security_connector_configs
                     where provider = 'AZURE' and account_id = :subscriptionId
                    """, Map.of("subscriptionId", target.subscriptionId()),
                    rs -> rs.next() ? rs.getObject("id", UUID.class) : null);
            UUID connectorId = existing == null ? UUID.randomUUID() : existing;
            jdbc.update("""
                    insert into ai_security_connector_configs as current (
                        id, tenant_id, provider, account_id, regions_json, enabled,
                        credential_profile_id, source_config_id, source_target_id,
                        provider_tenant_id, resource_families_json
                    ) values (
                        :id, :tenantId, 'AZURE', :subscriptionId, cast(:regions as jsonb), :enabled,
                        :profileId, :sourceConfigId, :sourceTargetId,
                        :providerTenantId, cast(:families as jsonb)
                    ) on conflict (tenant_id, provider, account_id) do update
                        set regions_json = excluded.regions_json,
                            enabled = excluded.enabled,
                            credential_profile_id = excluded.credential_profile_id,
                            source_config_id = excluded.source_config_id,
                            source_target_id = excluded.source_target_id,
                            provider_tenant_id = excluded.provider_tenant_id,
                            resource_families_json = excluded.resource_families_json,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("id", connectorId)
                    .addValue("tenantId", tenant.getId())
                    .addValue("subscriptionId", target.subscriptionId())
                    .addValue("regions", json(regions))
                    .addValue("enabled", request.enabled())
                    .addValue("profileId", profile.id())
                    .addValue("sourceConfigId", target.configId())
                    .addValue("sourceTargetId", target.targetId())
                    .addValue("providerTenantId", profile.azureTenantId())
                    .addValue("families", json(families)));
            return connectorId;
        }));
        return list(tenant).stream().filter(row -> row.id().equals(id)).findFirst().orElseThrow();
    }

    public ConnectionTestResponse test(Tenant tenant, UUID connectorId, String actor) {
        ConnectorSecret connector = secret(tenant, connectorId);
        CredentialTestResponse credential = credentials.test(
                tenant, connector.credentialProfileId(), connector.subscriptionId(), actor);
        Map<String, AzureAiManagementClient.AzureApiFailure> failures = Map.of();
        if (credential.success()) {
            var profile = credentials.secret(tenant, connector.credentialProfileId());
            failures = azure.discover(
                    credentials.tokenCredential(profile), connector.subscriptionId()).failures();
        }
        Map<String, AzureAiManagementClient.AzureApiFailure> probeFailures = failures;
        List<FamilyPermissionResult> families = connector.resourceFamilies().stream()
                .map(family -> permissionResult(family, credential.success(), probeFailures.get(family)))
                .toList();
        return new ConnectionTestResponse(
                credential.success(),
                credential.code(),
                credential.message(),
                credential.retryable(),
                UUID.randomUUID().toString(),
                families);
    }

    private FamilyPermissionResult permissionResult(
            String family,
            boolean authenticated,
            AzureAiManagementClient.AzureApiFailure failure
    ) {
        List<String> required = permissionMatrix.requiredPermissions(family);
        if (!authenticated) {
            return new FamilyPermissionResult(family, required, List.of(), required, "BLOCKED");
        }
        if ("AZURE_FOUNDRY_AGENTS".equals(family)
                || "AZURE_FOUNDRY_AGENT_TOOLS".equals(family)
                || family.startsWith("AZURE_SEARCH_INDEX")
                || family.startsWith("AZURE_SEARCH_SKILL")
                || family.startsWith("AZURE_SEARCH_DATA_SOURCE")) {
            return new FamilyPermissionResult(family, required, List.of(), List.of(), "NOT_PROBED");
        }
        if (failure == null) {
            return new FamilyPermissionResult(family, required, required, List.of(), "READY_FOR_DISCOVERY");
        }
        if ("ACCESS_DENIED".equals(failure.code())) {
            return new FamilyPermissionResult(family, required, List.of(), required, "MISSING_PERMISSION");
        }
        return new FamilyPermissionResult(family, required, List.of(), List.of(), failure.code());
    }

    public IngestionJobAcceptedResponse trigger(Tenant tenant, UUID connectorId, String requestedBy) {
        ConnectorSecret connector = secret(tenant, connectorId);
        if (!connector.enabled()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Azure AI Security connector is disabled");
        }
        credentials.secret(tenant, connector.credentialProfileId());
        return jobs.enqueueAiSecurityJob(
                tenant,
                connector.id(),
                IngestionJobService.JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY,
                "ai-security-azure",
                requestedBy);
    }

    public IngestionJobAcceptedResponse triggerTarget(Tenant tenant, UUID targetId, String requestedBy) {
        targets.require(tenant, targetId);
        UUID connectorId = tenantExecution.run(tenant, () -> jdbc.query("""
                select id
                  from ai_security_connector_configs
                 where provider = 'AZURE' and source_target_id = :targetId
                """, Map.of("targetId", targetId),
                rs -> rs.next() ? rs.getObject("id", UUID.class) : null));
        if (connectorId == null) {
            throw new ResponseStatusException(
                    HttpStatus.NOT_FOUND, "Azure AI Security connector binding not found for target");
        }
        return trigger(tenant, connectorId, requestedBy);
    }

    public AzurePolicyPermissionMatrix.RequirementsReport requirements() {
        return permissionMatrix.requirementsReport();
    }

    public ConnectorSecret secret(Tenant tenant, UUID connectorId) {
        return tenantExecution.run(tenant, () -> {
            List<ConnectorSecret> rows = jdbc.query("""
                    select id, account_id, provider_tenant_id, credential_profile_id,
                           source_target_id, regions_json::text, resource_families_json::text, enabled
                      from ai_security_connector_configs
                     where id = :id and provider = 'AZURE'
                    """, Map.of("id", connectorId), (rs, rowNum) -> new ConnectorSecret(
                    rs.getObject("id", UUID.class),
                    rs.getString("account_id"),
                    rs.getString("provider_tenant_id"),
                    rs.getObject("credential_profile_id", UUID.class),
                    rs.getObject("source_target_id", UUID.class),
                    readList(rs.getString("regions_json")),
                    readList(rs.getString("resource_families_json")),
                    rs.getBoolean("enabled")));
            if (rows.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Azure AI Security connector not found");
            }
            ConnectorSecret connector = rows.get(0);
            TargetSnapshot target = targets.require(tenant, connector.sourceTargetId());
            if (!connector.subscriptionId().equalsIgnoreCase(target.subscriptionId())) {
                throw new IllegalArgumentException("Azure connector subscription does not match its target");
            }
            return connector;
        });
    }

    private List<String> validateFamilies(List<String> requested) {
        List<String> values = requested == null || requested.isEmpty() ? DEFAULT_FAMILIES : requested;
        LinkedHashSet<String> result = new LinkedHashSet<>();
        for (String family : values) {
            String normalized = family == null ? "" : family.trim().toUpperCase();
            if (!permissionMatrix.resourceFamilies().contains(normalized)) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported Azure resource family");
            }
            result.add(normalized);
        }
        return List.copyOf(result);
    }

    private List<String> readList(String value) {
        if (value == null || value.isBlank()) {
            return List.of();
        }
        try {
            return objectMapper.readValue(value, new TypeReference<List<String>>() {});
        } catch (Exception exception) {
            throw new IllegalStateException("Invalid Azure AI Security connector configuration", exception);
        }
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to serialize Azure AI Security connector configuration", exception);
        }
    }

    public record ConnectorRequest(
            UUID credentialProfileId,
            UUID targetId,
            List<String> resourceFamilies,
            boolean enabled
    ) {
    }

    public record ConnectorResponse(
            UUID id,
            String subscriptionId,
            String azureTenantId,
            UUID credentialProfileId,
            UUID sourceConfigId,
            UUID sourceTargetId,
            List<String> regions,
            List<String> resourceFamilies,
            boolean enabled,
            Instant createdAt,
            Instant updatedAt
    ) {
    }

    public record ConnectorSecret(
            UUID id,
            String subscriptionId,
            String azureTenantId,
            UUID credentialProfileId,
            UUID sourceTargetId,
            List<String> regions,
            List<String> resourceFamilies,
            boolean enabled
    ) {
    }

    public record FamilyPermissionResult(
            String resourceFamily,
            List<String> required,
            List<String> granted,
            List<String> missing,
            String status
    ) {
    }

    public record ConnectionTestResponse(
            boolean success,
            String code,
            String message,
            boolean retryable,
            String correlationId,
            List<FamilyPermissionResult> resourceFamilies
    ) {
    }
}
