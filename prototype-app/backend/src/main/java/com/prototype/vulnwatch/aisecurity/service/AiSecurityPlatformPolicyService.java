package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry.PolicyDefinition;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AiSecurityPlatformPolicyService {

    private final NamedParameterJdbcTemplate jdbc;
    private final AiSecurityPolicyRegistry registry;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiGridFindingService canonicalFindings;
    private final AuditEventService auditEventService;

    public AiSecurityPlatformPolicyService(
            NamedParameterJdbcTemplate jdbc,
            AiSecurityPolicyRegistry registry,
            TenantService tenantService,
            TenantSchemaExecutionService tenantExecution,
            AiGridFindingService canonicalFindings,
            AuditEventService auditEventService
    ) {
        this.jdbc = jdbc;
        this.registry = registry;
        this.tenantService = tenantService;
        this.tenantExecution = tenantExecution;
        this.canonicalFindings = canonicalFindings;
        this.auditEventService = auditEventService;
    }

    public List<PlatformPolicyResponse> list() {
        return TenantContext.runAsPlatform(() -> registry.all().stream().map(this::response).toList());
    }

    public PlatformPolicyResponse update(
            String policyId, boolean available, boolean defaultEnabled, String actor) {
        PolicyDefinition definition = registry.find(policyId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown AI Security policy: " + policyId));
        TenantContext.runAsPlatform(() -> {
            jdbc.update("""
                    update platform.ai_security_policy_distribution
                       set available = :available,
                           default_enabled = :defaultEnabled,
                           updated_by = :actor,
                           updated_at = now()
                     where policy_id = :policyId
                    """, Map.of(
                    "policyId", policyId,
                    "available", available,
                    "defaultEnabled", defaultEnabled,
                    "actor", actor));
            for (Tenant tenant : tenantService.listActiveTenants()) {
                tenantExecution.run(tenant, () -> {
                    if (!available) {
                        canonicalFindings.closeForPolicy(tenant, policyId);
                    }
                    return null;
                });
            }
            auditEventService.record(
                    "ai_security.platform_policy.updated",
                    "ai_security_policy",
                    policyId,
                    "{\"available\":" + available + ",\"defaultEnabled\":" + defaultEnabled + "}");
            return null;
        });
        return response(definition);
    }

    private PlatformPolicyResponse response(PolicyDefinition definition) {
        return jdbc.queryForObject("""
                select available, default_enabled, updated_by, updated_at
                  from platform.ai_security_policy_distribution
                 where policy_id = :policyId
                """, Map.of("policyId", definition.id()), (rs, rowNum) -> new PlatformPolicyResponse(
                definition.id(),
                definition.version(),
                definition.name(),
                definition.severity(),
                rs.getBoolean("available"),
                rs.getBoolean("default_enabled"),
                rs.getString("updated_by"),
                rs.getTimestamp("updated_at").toInstant()));
    }

    public record PlatformPolicyResponse(
            String id,
            String version,
            String name,
            String severity,
            boolean available,
            boolean defaultEnabled,
            String updatedBy,
            Instant updatedAt
    ) {
    }
}
