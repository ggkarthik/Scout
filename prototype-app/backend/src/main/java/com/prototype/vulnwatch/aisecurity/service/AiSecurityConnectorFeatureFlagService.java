package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Tenant rollout flags. Environment booleans are evaluated separately as platform kill switches. */
@Service
public class AiSecurityConnectorFeatureFlagService {
    public enum Feature {
        AZURE_NEW_FOUNDRY, AZURE_CLASSIC_FOUNDRY, AZURE_ML_RUNTIME,
        AZURE_FOUNDRY_RUNTIME, COPILOT_DISCOVERY, COPILOT_RUNTIME
    }
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final AuditEventService audit;

    public AiSecurityConnectorFeatureFlagService(NamedParameterJdbcTemplate jdbc,
                                                 TenantSchemaExecutionService tenantExecution,
                                                 AuditEventService audit) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.audit = audit;
    }

    public boolean enabled(Tenant tenant, Feature feature, boolean platformKillSwitchAllows) {
        if (!platformKillSwitchAllows) return false;
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select enabled,kill_switch from ai_security_connector_feature_flags where feature_key=:feature
                """, Map.of("feature", feature.name()), rs -> rs.next() && rs.getBoolean(1) && !rs.getBoolean(2)));
    }

    public void assertEnabled(Tenant tenant, Feature feature, boolean platformKillSwitchAllows) {
        if (!enabled(tenant, feature, platformKillSwitchAllows)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "AI connector feature is disabled: " + feature.name());
        }
    }

    public List<Response> list(Tenant tenant) {
        Map<String, Response> stored = tenantExecution.run(tenant, () -> jdbc.query("""
                select feature_key,enabled,kill_switch,updated_by,updated_at
                  from ai_security_connector_feature_flags
                """, rs -> {
            java.util.LinkedHashMap<String, Response> result = new java.util.LinkedHashMap<>();
            while (rs.next()) result.put(rs.getString(1), new Response(rs.getString(1), rs.getBoolean(2),
                    rs.getBoolean(3), rs.getString(4), rs.getTimestamp(5).toInstant()));
            return result;
        }));
        return Arrays.stream(Feature.values()).map(feature -> stored.getOrDefault(feature.name(),
                new Response(feature.name(), false, false, null, null))).toList();
    }

    public Response update(Tenant tenant, Feature feature, Request request, String actor) {
        Response response = tenantExecution.run(tenant, () -> {
            jdbc.update("""
                    insert into ai_security_connector_feature_flags
                        (tenant_id,feature_key,enabled,kill_switch,updated_by)
                    values (:tenantId,:feature,:enabled,:killSwitch,:actor)
                    on conflict (tenant_id,feature_key) do update set
                        enabled=excluded.enabled,kill_switch=excluded.kill_switch,
                        updated_by=excluded.updated_by,updated_at=now()
                    """, new MapSqlParameterSource().addValue("tenantId", tenant.getId())
                    .addValue("feature", feature.name()).addValue("enabled", request.enabled())
                    .addValue("killSwitch", request.killSwitch()).addValue("actor", actor));
            return jdbc.query("""
                    select feature_key,enabled,kill_switch,updated_by,updated_at
                      from ai_security_connector_feature_flags where feature_key=:feature
                    """, Map.of("feature", feature.name()), rs -> {
                rs.next();
                return new Response(rs.getString(1), rs.getBoolean(2), rs.getBoolean(3), rs.getString(4),
                        rs.getTimestamp(5).toInstant());
            });
        });
        audit.record("ai_security.connector_feature_flag.updated", "ai_security_connector_feature",
                feature.name(), "{\"enabled\":" + request.enabled() + ",\"killSwitch\":" + request.killSwitch() + "}");
        return response;
    }

    public record Request(boolean enabled, boolean killSwitch) { }
    public record Response(String featureKey, boolean enabled, boolean killSwitch, String updatedBy, Instant updatedAt) { }
}
