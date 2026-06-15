package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class TenantEntitlementService {

    public static final String PLAN_PRO = "PRO";
    public static final String PLAN_ENTERPRISE = "ENTERPRISE";
    public static final String PLAN_DEMO = "DEMO";
    public static final String PLAN_PILOT = "PILOT";

    public static final String AI_INVESTIGATION_SUMMARY = "ai.investigation_summary";
    public static final String AI_SOLUTION_GENERATION = "ai.solution_generation";
    public static final String AI_REQUIRED_ACTIONS = "ai.required_actions";
    public static final String AI_FIX_GENERATION = "ai.fix_generation";
    public static final String AI_INVESTIGATION_AGENT = "ai.investigation_agent";
    public static final String AI_UPGRADE_RECOMMENDATION = "ai.upgrade_recommendation";

    private static final Set<String> KNOWN_PLANS = Set.of(PLAN_PRO, PLAN_ENTERPRISE, PLAN_DEMO, PLAN_PILOT);
    private static final String SOURCE_DEFAULT = "DEFAULT";
    private static final String SOURCE_PLAN = "PLAN";
    private static final String SOURCE_TENANT_OVERRIDE = "TENANT_OVERRIDE";

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final ObjectMapper objectMapper;

    public TenantEntitlementService(NamedParameterJdbcTemplate jdbcTemplate, ObjectMapper objectMapper) {
        this.jdbcTemplate = jdbcTemplate;
        this.objectMapper = objectMapper;
    }

    public Map<String, Boolean> snapshot(Tenant tenant) {
        LinkedHashMap<String, Boolean> snapshot = new LinkedHashMap<>();
        for (ResolvedEntitlement entitlement : resolveAll(tenant)) {
            snapshot.put(entitlement.key(), entitlement.enabled());
        }
        return snapshot;
    }

    public boolean isEnabled(Tenant tenant, String entitlementKey) {
        return resolve(tenant, entitlementKey).enabled();
    }

    public ResolvedEntitlement resolve(Tenant tenant, String entitlementKey) {
        String key = normalizeKey(entitlementKey);
        String commercialPlan = commercialPlanCode(tenant);
        String effectivePlan = effectivePlanCode(commercialPlan);

        EntitlementDefinition definition = loadDefinitions().stream()
                .filter(candidate -> candidate.key().equals(key))
                .findFirst()
                .orElse(new EntitlementDefinition(key, "UNCATEGORIZED", "BOOLEAN", null));

        PlanEntitlementRow planRow = loadPlanEntitlements(effectivePlan).get(key);
        TenantOverrideRow overrideRow = tenant == null ? null : loadTenantOverrides(tenant.getId()).get(key);

        boolean enabled = false;
        String source = SOURCE_DEFAULT;
        Map<String, Object> config = Map.of();

        if (planRow != null) {
            enabled = planRow.enabled();
            config = planRow.config();
            source = SOURCE_PLAN;
        }
        if (overrideRow != null) {
            enabled = overrideRow.enabled();
            config = overrideRow.config();
            source = SOURCE_TENANT_OVERRIDE;
        }

        return new ResolvedEntitlement(
                definition.key(),
                definition.category(),
                enabled,
                source,
                commercialPlan,
                config
        );
    }

    public List<ResolvedEntitlement> resolveAll(Tenant tenant) {
        String commercialPlan = commercialPlanCode(tenant);
        String effectivePlan = effectivePlanCode(commercialPlan);
        Map<String, PlanEntitlementRow> planRows = loadPlanEntitlements(effectivePlan);
        Map<String, TenantOverrideRow> overrideRows = tenant == null ? Map.of() : loadTenantOverrides(tenant.getId());
        List<ResolvedEntitlement> entitlements = new ArrayList<>();
        for (EntitlementDefinition definition : loadDefinitions()) {
            PlanEntitlementRow planRow = planRows.get(definition.key());
            TenantOverrideRow overrideRow = overrideRows.get(definition.key());
            boolean enabled = false;
            String source = SOURCE_DEFAULT;
            Map<String, Object> config = Map.of();
            if (planRow != null) {
                enabled = planRow.enabled();
                config = planRow.config();
                source = SOURCE_PLAN;
            }
            if (overrideRow != null) {
                enabled = overrideRow.enabled();
                config = overrideRow.config();
                source = SOURCE_TENANT_OVERRIDE;
            }
            entitlements.add(new ResolvedEntitlement(
                    definition.key(),
                    definition.category(),
                    enabled,
                    source,
                    commercialPlan,
                    config
            ));
        }
        return entitlements;
    }

    public List<TenantEntitlementOverrideRecord> listOverrides(UUID tenantId) {
        if (tenantId == null) {
            return List.of();
        }
        return jdbcTemplate.query("""
                select id,
                       tenant_id,
                       entitlement_key,
                       enabled,
                       config_json,
                       reason,
                       expires_at,
                       created_by,
                       created_at,
                       updated_at
                  from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                 order by entitlement_key asc
                """, Map.of("tenantId", tenantId), (rs, rowNum) -> toOverrideRecord(rs));
    }

    public TenantEntitlementOverrideRecord upsertOverride(
            UUID tenantId,
            String entitlementKey,
            boolean enabled,
            Map<String, Object> config,
            String reason,
            Instant expiresAt,
            UUID createdBy
    ) {
        UUID overrideId = existingOverrideId(tenantId, entitlementKey);
        Instant now = Instant.now();
        String configJson = writeJson(config);
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("id", overrideId == null ? UUID.randomUUID() : overrideId)
                .addValue("tenantId", tenantId)
                .addValue("entitlementKey", normalizeKey(entitlementKey))
                .addValue("enabled", enabled)
                .addValue("configJson", configJson)
                .addValue("reason", trimToNull(reason))
                .addValue("expiresAt", expiresAt == null ? null : Timestamp.from(expiresAt))
                .addValue("createdBy", createdBy)
                .addValue("createdAt", Timestamp.from(now))
                .addValue("updatedAt", Timestamp.from(now));
        jdbcTemplate.update("""
                insert into platform.tenant_entitlement_overrides (
                    id, tenant_id, entitlement_key, enabled, config_json, reason, expires_at, created_by, created_at, updated_at
                ) values (
                    :id, :tenantId, :entitlementKey, :enabled, cast(:configJson as jsonb), :reason, :expiresAt, :createdBy, :createdAt, :updatedAt
                )
                on conflict (tenant_id, entitlement_key) do update
                    set enabled = excluded.enabled,
                        config_json = excluded.config_json,
                        reason = excluded.reason,
                        expires_at = excluded.expires_at,
                        created_by = excluded.created_by,
                        updated_at = excluded.updated_at
                """, params);
        return listOverrides(tenantId).stream()
                .filter(override -> override.entitlementKey().equals(normalizeKey(entitlementKey)))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Failed to load saved entitlement override"));
    }

    public void deleteOverride(UUID tenantId, String entitlementKey) {
        jdbcTemplate.update("""
                delete from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                   and entitlement_key = :entitlementKey
                """, Map.of("tenantId", tenantId, "entitlementKey", normalizeKey(entitlementKey)));
    }

    public String commercialPlanCode(Tenant tenant) {
        if (tenant == null) {
            return PLAN_PRO;
        }
        String raw = normalizePlanCode(tenant.getPlanCode());
        return raw == null ? PLAN_PRO : raw;
    }

    public String effectivePlanCode(String commercialPlanCode) {
        String normalized = normalizePlanCode(commercialPlanCode);
        if (normalized == null) {
            return PLAN_PRO;
        }
        return switch (normalized) {
            case PLAN_ENTERPRISE -> PLAN_ENTERPRISE;
            case PLAN_DEMO -> PLAN_DEMO;
            case PLAN_PRO -> PLAN_PRO;
            case PLAN_PILOT -> PLAN_PRO;
            default -> PLAN_PRO;
        };
    }

    private List<EntitlementDefinition> loadDefinitions() {
        return jdbcTemplate.query("""
                select key, category, value_type, description
                  from platform.entitlement_definitions
                 order by category asc, key asc
                """, (rs, rowNum) -> new EntitlementDefinition(
                rs.getString("key"),
                rs.getString("category"),
                rs.getString("value_type"),
                rs.getString("description")
        ));
    }

    private Map<String, PlanEntitlementRow> loadPlanEntitlements(String planCode) {
        LinkedHashMap<String, PlanEntitlementRow> rows = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select entitlement_key, enabled, config_json
                  from platform.plan_entitlements
                 where plan_code = :planCode
                """, Map.of("planCode", effectivePlanCode(planCode)), (rs) -> {
            rows.put(rs.getString("entitlement_key"), new PlanEntitlementRow(
                    rs.getBoolean("enabled"),
                    readJsonMap(rs.getString("config_json"))
            ));
        });
        return rows;
    }

    private Map<String, TenantOverrideRow> loadTenantOverrides(UUID tenantId) {
        LinkedHashMap<String, TenantOverrideRow> rows = new LinkedHashMap<>();
        jdbcTemplate.query("""
                select entitlement_key, enabled, config_json
                  from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                   and (expires_at is null or expires_at > :now)
                """, Map.of("tenantId", tenantId, "now", Timestamp.from(Instant.now())), (rs) -> {
            rows.put(rs.getString("entitlement_key"), new TenantOverrideRow(
                    rs.getBoolean("enabled"),
                    readJsonMap(rs.getString("config_json"))
            ));
        });
        return rows;
    }

    private UUID existingOverrideId(UUID tenantId, String entitlementKey) {
        List<UUID> ids = jdbcTemplate.query("""
                select id
                  from platform.tenant_entitlement_overrides
                 where tenant_id = :tenantId
                   and entitlement_key = :entitlementKey
                """, Map.of("tenantId", tenantId, "entitlementKey", normalizeKey(entitlementKey)),
                (rs, rowNum) -> rs.getObject("id", UUID.class));
        return ids.isEmpty() ? null : ids.get(0);
    }

    private TenantEntitlementOverrideRecord toOverrideRecord(ResultSet rs) throws SQLException {
        return new TenantEntitlementOverrideRecord(
                rs.getObject("id", UUID.class),
                rs.getObject("tenant_id", UUID.class),
                rs.getString("entitlement_key"),
                rs.getBoolean("enabled"),
                readJsonMap(rs.getString("config_json")),
                rs.getString("reason"),
                rs.getTimestamp("expires_at") == null ? null : rs.getTimestamp("expires_at").toInstant(),
                rs.getObject("created_by", UUID.class),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant()
        );
    }

    private String normalizePlanCode(String planCode) {
        if (planCode == null || planCode.isBlank()) {
            return null;
        }
        String normalized = planCode.trim().toUpperCase();
        return KNOWN_PLANS.contains(normalized) ? normalized : normalized;
    }

    private String normalizeKey(String entitlementKey) {
        if (entitlementKey == null || entitlementKey.isBlank()) {
            throw new IllegalArgumentException("entitlementKey is required");
        }
        return entitlementKey.trim();
    }

    private String writeJson(Map<String, Object> config) {
        try {
            return config == null || config.isEmpty() ? null : objectMapper.writeValueAsString(config);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to serialize entitlement config", ex);
        }
    }

    private Map<String, Object> readJsonMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception ex) {
            return Map.of();
        }
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private record EntitlementDefinition(
            String key,
            String category,
            String valueType,
            String description
    ) {}

    private record PlanEntitlementRow(
            boolean enabled,
            Map<String, Object> config
    ) {}

    private record TenantOverrideRow(
            boolean enabled,
            Map<String, Object> config
    ) {}

    public record ResolvedEntitlement(
            String key,
            String category,
            boolean enabled,
            String source,
            String planCode,
            Map<String, Object> config
    ) {}

    public record TenantEntitlementOverrideRecord(
            UUID id,
            UUID tenantId,
            String entitlementKey,
            boolean enabled,
            Map<String, Object> config,
            String reason,
            Instant expiresAt,
            UUID createdBy,
            Instant createdAt,
            Instant updatedAt
    ) {}
}
