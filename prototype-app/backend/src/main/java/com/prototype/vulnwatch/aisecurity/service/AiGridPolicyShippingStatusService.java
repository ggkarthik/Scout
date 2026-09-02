package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.TenantContext;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;

/** Catalog-only shipping verification. Never consults tenant runtime evidence. */
@Service
public class AiGridPolicyShippingStatusService {
    private static final String BUNDLED = "policy-packages/agcf/%";
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public AiGridPolicyShippingStatusService(NamedParameterJdbcTemplate jdbc, ObjectMapper mapper) { this.jdbc = jdbc; this.mapper = mapper; }

    public ShippingStatus status() {
        return TenantContext.runAsPlatform(() -> {
            Map<String, String> expectedDigests = bundledManifest();
            long expected = expectedDigests.size();
            long installed = count("select count(*) from platform.ai_grid_policy_versions where package_source_ref like :bundled", Map.of("bundled", BUNDLED));
            long published = count("select count(*) from platform.ai_grid_policy_versions where package_source_ref like :bundled and lifecycle='PUBLISHED'", Map.of("bundled", BUNDLED));
            long distributed = count("""
                    select count(*) from platform.ai_grid_policy_versions p join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                     where p.package_source_ref like :bundled and p.lifecycle='PUBLISHED' and d.available
                       and d.pinned_version=p.version
                    """, Map.of("bundled", BUNDLED));
            long digestMatched = expectedDigests.entrySet().stream().filter(entry -> count("""
                    select count(*) from platform.ai_grid_policy_versions
                     where policy_id=:policyId and version=:version and package_digest=:digest
                    """, Map.of("policyId", entry.getKey().split("@", 2)[0], "version", entry.getKey().split("@", 2)[1],
                    "digest", entry.getValue())) == 1).count();
            long pending = count("select count(*) from platform.ai_grid_policy_rollout_tasks where status in ('PENDING','PROCESSING','WAITING_FOR_SNAPSHOT','FAILED')", Map.of());
            List<String> blockers = new java.util.ArrayList<>();
            if (expected != 159) blockers.add("Expected 159 bundled policies but found " + expected);
            if (installed != expected) blockers.add("Bundled catalog is not fully installed");
            if (digestMatched != expected) blockers.add("One or more bundled package digests are missing or invalid");
            return new ShippingStatus(expected, installed, published, distributed, digestMatched, pending, List.copyOf(blockers));
        });
    }

    private long count(String sql, Map<String, ?> parameters) {
        Long value = jdbc.queryForObject(sql, parameters, Long.class);
        return value == null ? 0 : value;
    }

    private Map<String, String> bundledManifest() {
        Map<String, String> result = new HashMap<>();
        for (String resource : List.of("ai-grid/phase-1-manifest.json", "ai-grid/phase-2-manifest.json")) {
            try (InputStream input = getClass().getClassLoader().getResourceAsStream(resource)) {
                if (input == null) {
                    if (resource.endsWith("phase-2-manifest.json")) continue;
                    throw new IllegalStateException("Bundled AI Grid shipping manifest is missing: " + resource);
                }
                JsonNode policies = mapper.readTree(new InputStreamReader(input, StandardCharsets.UTF_8)).path("policies");
                for (JsonNode policy : policies) result.put(policy.path("policyId").asText() + "@" + policy.path("version").asText(), policy.path("digest").asText());
            } catch (Exception ex) {
                throw new IllegalStateException("Unable to read bundled AI Grid shipping manifest: " + resource, ex);
            }
        }
        return result;
    }

    public record ShippingStatus(long expectedPolicies, long installedPolicies, long publishedPolicies,
                                 long distributedPolicies, long digestMatchedPolicies,
                                 long rolloutPendingTenants, List<String> blockers) {}
}
