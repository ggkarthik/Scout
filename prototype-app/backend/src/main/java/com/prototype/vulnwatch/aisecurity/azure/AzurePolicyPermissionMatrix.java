package com.prototype.vulnwatch.aisecurity.azure;

import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyRegistry;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;
import org.yaml.snakeyaml.Yaml;

@Component
public class AzurePolicyPermissionMatrix {

    private static final String RESOURCE =
            "ai-security/azure-policy-permission-matrix.yaml";

    private final int version;
    private final Map<String, FamilyPermission> families;
    private final List<PolicyPermission> policies;
    private final List<String> prohibitedActions;

    public AzurePolicyPermissionMatrix(AiSecurityPolicyRegistry registry) {
        Map<String, Object> root = load();
        this.version = integer(root.get("version"));
        if (version != 1 || !"AZURE".equals(text(root.get("provider")))) {
            throw new IllegalStateException("Unsupported Azure policy-permission matrix");
        }
        this.prohibitedActions = List.copyOf(strings(map(root.get("defaults")).get("prohibited_actions")));
        this.families = parseFamilies(map(root.get("family_permissions")));
        this.policies = parsePolicies(list(root.get("policies")));
        validate(registry);
    }

    public int version() {
        return version;
    }

    public Set<String> resourceFamilies() {
        return families.keySet();
    }

    public FamilyPermission family(String resourceFamily) {
        FamilyPermission permission = families.get(resourceFamily);
        if (permission == null) {
            throw new IllegalArgumentException("Unsupported Azure resource family");
        }
        return permission;
    }

    public List<String> requiredPermissions(String resourceFamily) {
        return family(resourceFamily).actions();
    }

    public RequirementsReport requirementsReport() {
        return new RequirementsReport(
                version,
                "AZURE",
                families.values().stream().toList(),
                policies,
                prohibitedActions,
                roleTemplate());
    }

    public AzureCustomRoleTemplate roleTemplate() {
        TreeSet<String> actions = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        families.values().forEach(family -> actions.addAll(family.actions()));
        return new AzureCustomRoleTemplate(
                "NoScan AI Security Discovery",
                true,
                "Read-only Azure AI inventory and configuration evidence required by shipped policies.",
                List.copyOf(actions),
                prohibitedActions,
                List.of(),
                List.of(),
                List.of("/subscriptions/<subscription-id>"));
    }

    private void validate(AiSecurityPolicyRegistry registry) {
        if (!families.keySet().equals(AiSecurityAzureConnectorService.RESOURCE_FAMILIES)) {
            Set<String> missing = new TreeSet<>(AiSecurityAzureConnectorService.RESOURCE_FAMILIES);
            missing.removeAll(families.keySet());
            Set<String> unknown = new TreeSet<>(families.keySet());
            unknown.removeAll(AiSecurityAzureConnectorService.RESOURCE_FAMILIES);
            throw new IllegalStateException(
                    "Azure matrix family drift; missing=" + missing + ", unknown=" + unknown);
        }
        Set<String> prohibited = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        prohibited.addAll(prohibitedActions);
        for (FamilyPermission family : families.values()) {
            if (family.actions().isEmpty()) {
                throw new IllegalStateException("Azure matrix family has no actions: " + family.resourceFamily());
            }
            for (String action : family.actions()) {
                if (prohibited.contains(action)) {
                    throw new IllegalStateException(
                            "Azure matrix includes prohibited action: " + action);
                }
            }
        }

        Map<String, PolicyPermission> byId = new LinkedHashMap<>();
        for (PolicyPermission policy : policies) {
            if (byId.putIfAbsent(policy.id(), policy) != null) {
                throw new IllegalStateException("Duplicate Azure matrix policy: " + policy.id());
            }
            if (!families.keySet().containsAll(policy.families())) {
                throw new IllegalStateException("Azure matrix policy references an unknown family: " + policy.id());
            }
        }
        var registryPolicies = registry.all().stream()
                .filter(policy -> policy.id().startsWith("AZURE_"))
                .toList();
        if (registryPolicies.size() != byId.size()) {
            throw new IllegalStateException("Azure matrix and policy registry have different policy counts");
        }
        registryPolicies.forEach(policy -> {
            PolicyPermission matrixPolicy = byId.get(policy.id());
            if (matrixPolicy == null
                    || !policy.version().equals(matrixPolicy.version())
                    || !new LinkedHashSet<>(policy.requiredResourceFamilies())
                            .equals(new LinkedHashSet<>(matrixPolicy.families()))) {
                throw new IllegalStateException("Azure matrix policy drift: " + policy.id());
            }
        });
    }

    private Map<String, FamilyPermission> parseFamilies(Map<String, Object> values) {
        Map<String, FamilyPermission> result = new LinkedHashMap<>();
        values.forEach((family, value) -> {
            Map<String, Object> config = map(value);
            result.put(family, new FamilyPermission(
                    family,
                    text(config.get("api_version")),
                    text(config.get("role")),
                    List.copyOf(strings(config.get("actions")))));
        });
        return Map.copyOf(result);
    }

    private List<PolicyPermission> parsePolicies(List<Object> values) {
        List<PolicyPermission> result = new ArrayList<>();
        for (Object value : values) {
            Map<String, Object> policy = map(value);
            result.add(new PolicyPermission(
                    text(policy.get("id")),
                    text(policy.get("version")),
                    List.copyOf(strings(policy.get("families"))),
                    List.copyOf(strings(policy.get("facts"))),
                    List.copyOf(strings(policy.get("scopes"))),
                    text(policy.get("connector_test"))));
        }
        return List.copyOf(result);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> load() {
        try (InputStream input = new ClassPathResource(RESOURCE).getInputStream()) {
            Object value = new Yaml().load(input);
            return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to load Azure policy-permission matrix", exception);
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> map(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    @SuppressWarnings("unchecked")
    private List<Object> list(Object value) {
        return value instanceof List<?> list ? (List<Object>) list : List.of();
    }

    private List<String> strings(Object value) {
        return list(value).stream().map(this::text).filter(item -> !item.isBlank()).toList();
    }

    private String text(Object value) {
        return value == null ? "" : String.valueOf(value).trim();
    }

    private int integer(Object value) {
        return value instanceof Number number
                ? number.intValue()
                : Integer.parseInt(text(value));
    }

    public record FamilyPermission(
            String resourceFamily,
            String apiVersion,
            String role,
            List<String> actions
    ) {
    }

    public record PolicyPermission(
            String policyId,
            String version,
            List<String> resourceFamilies,
            List<String> facts,
            List<String> scopes,
            String connectorTest
    ) {
        public String id() {
            return policyId;
        }

        public List<String> families() {
            return resourceFamilies;
        }
    }

    public record AzureCustomRoleTemplate(
            String name,
            boolean isCustom,
            String description,
            List<String> actions,
            List<String> notActions,
            List<String> dataActions,
            List<String> notDataActions,
            List<String> assignableScopes
    ) {
    }

    public record RequirementsReport(
            int matrixVersion,
            String provider,
            List<FamilyPermission> resourceFamilies,
            List<PolicyPermission> policies,
            List<String> prohibitedActions,
            AzureCustomRoleTemplate roleTemplate
    ) {
    }
}
