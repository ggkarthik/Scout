package com.prototype.vulnwatch.aisecurity.copilot;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureCredentialService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Copilot Studio configuration boundary; Dataverse discovery and execution are independently gated. */
@Service
public class CopilotStudioConnectorService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final AiSecurityAzureCredentialService credentials;
    private final ObjectMapper json;

    public CopilotStudioConnectorService(NamedParameterJdbcTemplate jdbc, TenantSchemaExecutionService tenantExecution,
                                         TransactionTemplate transactions, AiSecurityAzureCredentialService credentials,
                                         ObjectMapper json) {
        this.jdbc = jdbc; this.tenantExecution = tenantExecution; this.transactions = transactions; this.credentials = credentials; this.json=json;
    }

    public List<Response> list(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id,organization_url,credential_profile_id,discovery_enabled,execution_enabled,kill_switch,schedule_cron,
                       allowed_dataverse_hosts_json,created_at,updated_at
                  from ai_security_copilot_studio_configs order by organization_url
                """, (rs, row) -> new Response(rs.getObject("id", UUID.class), rs.getString("organization_url"),
                rs.getObject("credential_profile_id", UUID.class), rs.getBoolean("discovery_enabled"), rs.getBoolean("execution_enabled"),
                rs.getBoolean("kill_switch"), rs.getString("schedule_cron"), hosts(rs.getString("allowed_dataverse_hosts_json")),
                rs.getTimestamp("created_at").toInstant(), rs.getTimestamp("updated_at").toInstant())));
    }

    public Response required(Tenant tenant, UUID id) {
        return list(tenant).stream().filter(item -> item.id().equals(id)).findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Copilot Studio connector was not found"));
    }

    public Response save(Tenant tenant, Request request) {
        if (request == null || request.credentialProfileId() == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Credential profile is required");
        URI organization = validateOrganizationUrl(request.organizationUrl());
        List<String> allowedHosts = validateHostPolicy(request.allowedDataverseHosts(), organization.getHost());
        String organizationUrl = organization.toString();
        String schedule = validateSchedule(request.scheduleCron());
        credentials.secret(tenant, request.credentialProfileId()); // only a tenant-owned profile may be referenced
        UUID id = tenantExecution.run(tenant, () -> transactions.execute(status -> {
            UUID value = jdbc.query("select id from ai_security_copilot_studio_configs where organization_url=:url", Map.of("url", organizationUrl),
                    rs -> rs.next() ? rs.getObject(1, UUID.class) : UUID.randomUUID());
            jdbc.update("""
                    insert into ai_security_copilot_studio_configs as c (id,tenant_id,organization_url,credential_profile_id,discovery_enabled,execution_enabled,kill_switch,schedule_cron,allowed_dataverse_hosts_json)
                    values (:id,:tenantId,:url,:profile,:discovery,:execution,:kill,:schedule,cast(:hosts as jsonb))
                    on conflict (tenant_id,organization_url) do update set credential_profile_id=excluded.credential_profile_id,
                        discovery_enabled=excluded.discovery_enabled,execution_enabled=excluded.execution_enabled,kill_switch=excluded.kill_switch,
                        schedule_cron=excluded.schedule_cron,allowed_dataverse_hosts_json=excluded.allowed_dataverse_hosts_json,updated_at=now()
                    """, new MapSqlParameterSource().addValue("id", value).addValue("tenantId", tenant.getId()).addValue("url", organizationUrl)
                    .addValue("profile", request.credentialProfileId()).addValue("discovery", request.discoveryEnabled())
                    .addValue("execution", request.executionEnabled()).addValue("kill", request.killSwitch())
                    .addValue("schedule", schedule).addValue("hosts", toJson(allowedHosts)));
            return value;
        }));
        return list(tenant).stream().filter(item -> item.id().equals(id)).findFirst().orElseThrow();
    }

    private static URI validateOrganizationUrl(String value) {
        try {
            URI uri = URI.create(value == null ? "" : value.trim());
            String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                    || (uri.getPort() != -1 && uri.getPort() != 443) || uri.getQuery() != null || uri.getFragment() != null
                    || (uri.getPath() != null && !uri.getPath().isBlank() && !"/".equals(uri.getPath()))
                    || !host.endsWith(".dynamics.com")) throw new IllegalArgumentException();
            return URI.create("https://" + host);
        } catch (RuntimeException error) { throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Copilot Studio organization URL must be an allowlisted HTTPS Dataverse host"); }
    }
    private static List<String> validateHostPolicy(List<String> requested, String organizationHost) {
        List<String> values = requested == null || requested.isEmpty() ? List.of(organizationHost) : requested;
        List<String> normalized = values.stream().map(value -> value == null ? "" : value.trim().toLowerCase())
                .distinct().toList();
        if (normalized.stream().anyMatch(value -> value.isBlank() || value.contains("*") || value.contains("/")
                || value.contains("@") || value.contains(":") || !value.endsWith(".dynamics.com"))
                || !normalized.contains(organizationHost.toLowerCase())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Dataverse host policy must contain the exact organization host and cannot contain wildcards");
        }
        return normalized;
    }
    private String toJson(Object value) { try { return json.writeValueAsString(value); }
        catch (Exception error) { throw new IllegalStateException("Unable to encode Dataverse host policy", error); } }
    private List<String> hosts(String value) { try { return json.readValue(value, new TypeReference<List<String>>() { }); }
        catch (Exception error) { return List.of(); } }
    private static String validateSchedule(String value) {
        String schedule = value == null || value.isBlank() ? "0 0 * * * *" : value.trim();
        try { org.springframework.scheduling.support.CronExpression.parse(schedule); return schedule; }
        catch (IllegalArgumentException error) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Copilot Studio schedule must be a valid six-field cron expression");
        }
    }
    public record Request(String organizationUrl, UUID credentialProfileId, boolean discoveryEnabled, boolean executionEnabled, boolean killSwitch, String scheduleCron, List<String> allowedDataverseHosts) { }
    public record Response(UUID id, String organizationUrl, UUID credentialProfileId, boolean discoveryEnabled, boolean executionEnabled, boolean killSwitch, String scheduleCron, List<String> allowedDataverseHosts, Instant createdAt, Instant updatedAt) { }
}
