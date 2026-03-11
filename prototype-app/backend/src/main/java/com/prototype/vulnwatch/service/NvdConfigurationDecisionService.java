package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.VulnerabilityConfigExpr;
import com.prototype.vulnwatch.util.CpeUtil;
import com.prototype.vulnwatch.util.IdentityUtil;
import com.prototype.vulnwatch.util.PurlUtil;
import com.prototype.vulnwatch.util.VersionUtil;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class NvdConfigurationDecisionService {

    private final ObjectMapper objectMapper;

    public NvdConfigurationDecisionService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ApplicabilityDecisionService.ApplicabilityDecision evaluate(
            InventoryComponent component,
            List<VulnerabilityConfigExpr> expressions
    ) {
        Map<String, Object> trace = new LinkedHashMap<>();
        trace.put("componentPackage", component.getPackageName());
        trace.put("componentVersion", component.getVersion());
        trace.put("componentPurl", component.getPurl());
        trace.put("componentDigest", component.getComponentDigest());

        if (expressions == null || expressions.isEmpty()) {
            trace.put("finalReason", "nvd_tree_unavailable");
            // BLG-003: No NVD config data means we cannot determine applicability — return UNKNOWN,
            // not TRUE (affected). Defaulting to TRUE generates systematic false positives for every
            // CVE that lacks detailed NVD configuration entries.
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                    "nvd_tree_unavailable",
                    trace
            );
        }

        Map<Integer, List<VulnerabilityConfigExpr>> rootsByConfig = expressions.stream()
                .filter(Objects::nonNull)
                .filter(expr -> expr.getParentPath() == null || expr.getParentPath().isBlank())
                .collect(Collectors.groupingBy(
                        VulnerabilityConfigExpr::getConfigIndex,
                        LinkedHashMap::new,
                        Collectors.toList()
                ));

        if (rootsByConfig.isEmpty()) {
            trace.put("finalReason", "nvd_tree_unavailable");
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                    "nvd_tree_unavailable",
                    trace
            );
        }

        List<Map<String, Object>> configTrace = new ArrayList<>();
        TriState finalState = TriState.FALSE;
        boolean sawUnknown = false;

        for (Map.Entry<Integer, List<VulnerabilityConfigExpr>> entry : rootsByConfig.entrySet()) {
            int configIndex = entry.getKey();
            List<VulnerabilityConfigExpr> roots = entry.getValue().stream()
                    .sorted(Comparator.comparing(VulnerabilityConfigExpr::getNodePath, Comparator.nullsLast(String::compareTo)))
                    .toList();

            TriState configResult = TriState.FALSE;
            List<Map<String, Object>> nodeTrace = new ArrayList<>();
            for (VulnerabilityConfigExpr root : roots) {
                TriState rootState = evaluateNode(component, parseJson(root.getExprJson()), root.getNodePath(), nodeTrace);
                configResult = or(configResult, rootState);
            }

            Map<String, Object> configEntry = new LinkedHashMap<>();
            configEntry.put("configIndex", configIndex);
            configEntry.put("result", configResult.name());
            configEntry.put("roots", roots.stream().map(VulnerabilityConfigExpr::getNodePath).toList());
            configEntry.put("nodes", nodeTrace);
            configTrace.add(configEntry);

            finalState = or(finalState, configResult);
            sawUnknown = sawUnknown || configResult == TriState.UNKNOWN;
            if (finalState == TriState.TRUE) {
                break;
            }
        }

        trace.put("configurations", configTrace);
        if (finalState == TriState.TRUE) {
            trace.put("finalReason", "nvd_config_match");
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.TRUE,
                    "nvd_config_match",
                    trace
            );
        }
        if (sawUnknown) {
            trace.put("finalReason", "nvd_config_unknown");
            return new ApplicabilityDecisionService.ApplicabilityDecision(
                    ApplicabilityDecisionService.ApplicabilityResult.UNKNOWN,
                    "nvd_config_unknown",
                    trace
            );
        }
        trace.put("finalReason", "nvd_config_no_match");
        return new ApplicabilityDecisionService.ApplicabilityDecision(
                ApplicabilityDecisionService.ApplicabilityResult.FALSE,
                "nvd_config_no_match",
                trace
        );
    }

    private TriState evaluateNode(
            InventoryComponent component,
            JsonNode node,
            String nodePath,
            List<Map<String, Object>> nodeTrace
    ) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return TriState.UNKNOWN;
        }

        String operator = normalizeOperator(node.path("operator").asText(""));
        boolean negate = node.path("negate").asBoolean(false);
        List<TriState> operands = new ArrayList<>();

        JsonNode cpeMatch = node.path("cpeMatch");
        if (cpeMatch.isArray()) {
            for (JsonNode match : cpeMatch) {
                operands.add(evaluateMatch(component, match));
            }
        }

        JsonNode children = node.path("children");
        if (children.isArray()) {
            for (JsonNode child : children) {
                operands.add(evaluateNode(component, child, nodePath + ".child", nodeTrace));
            }
        }

        TriState result = combine(operator, operands);
        if (negate) {
            result = negate(result);
        }

        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("nodePath", nodePath);
        entry.put("operator", operator);
        entry.put("negate", negate);
        entry.put("operandCount", operands.size());
        entry.put("result", result.name());
        nodeTrace.add(entry);
        return result;
    }

    private TriState evaluateMatch(InventoryComponent component, JsonNode match) {
        if (match == null || match.isMissingNode() || match.isNull()) {
            return TriState.UNKNOWN;
        }
        String criteria = textOrNull(match.path("criteria"));
        if (criteria == null) {
            return TriState.UNKNOWN;
        }

        boolean vulnerable = !match.has("vulnerable") || match.path("vulnerable").asBoolean(true);
        CpeUtil.ParsedCpe cpe = CpeUtil.parse(criteria);
        IdentityMatch identityMatch = matchesComponentIdentity(component, cpe);
        if (identityMatch == IdentityMatch.UNKNOWN) {
            return TriState.UNKNOWN;
        }

        // BLG-005: use ecosystem-specific version scheme instead of UNKNOWN for all ecosystems.
        VersionScheme scheme = schemeForComponent(component);
        TriState base = evaluateVersion(component.getVersion(), cpe, match, scheme);
        if (vulnerable) {
            return base;
        }
        return negate(base);
    }

    private TriState evaluateVersion(String componentVersion, CpeUtil.ParsedCpe cpe, JsonNode match, VersionScheme scheme) {
        String start = textOrNull(match.path("versionStartIncluding"));
        Boolean startInclusive = null;
        if (start == null) {
            start = textOrNull(match.path("versionStartExcluding"));
            if (start != null) {
                startInclusive = false;
            }
        } else {
            startInclusive = true;
        }

        String end = textOrNull(match.path("versionEndIncluding"));
        Boolean endInclusive = null;
        if (end == null) {
            end = textOrNull(match.path("versionEndExcluding"));
            if (end != null) {
                endInclusive = false;
            }
        } else {
            endInclusive = true;
        }

        String exact = wildcard(cpe.version()) ? null : cpe.version();
        if (start != null || end != null) {
            exact = null;
        }

        if (exact == null && start == null && end == null) {
            return TriState.TRUE;
        }
        if (componentVersion == null || componentVersion.isBlank()) {
            return TriState.UNKNOWN;
        }

        try {
            if (exact != null) {
                return VersionUtil.compare(componentVersion, exact, scheme) == 0 ? TriState.TRUE : TriState.FALSE;
            }
            if (start != null) {
                int startCompare = VersionUtil.compare(componentVersion, start, scheme);
                boolean inclusive = startInclusive == null || startInclusive;
                if (inclusive && startCompare < 0) {
                    return TriState.FALSE;
                }
                if (!inclusive && startCompare <= 0) {
                    return TriState.FALSE;
                }
            }
            if (end != null) {
                int endCompare = VersionUtil.compare(componentVersion, end, scheme);
                boolean inclusive = endInclusive == null || endInclusive;
                if (inclusive && endCompare > 0) {
                    return TriState.FALSE;
                }
                if (!inclusive && endCompare >= 0) {
                    return TriState.FALSE;
                }
            }
            return TriState.TRUE;
        } catch (RuntimeException ignored) {
            return TriState.UNKNOWN;
        }
    }

    private IdentityMatch matchesComponentIdentity(InventoryComponent component, CpeUtil.ParsedCpe cpe) {
        String cpeProduct = IdentityUtil.normalize(cpe.product());
        if (cpeProduct.isBlank()) {
            return IdentityMatch.UNKNOWN;
        }

        String foldedCpeProduct = foldIdentityToken(cpeProduct);
        LinkedHashSet<String> componentTokens = componentIdentityTokens(component);
        if (componentTokens.isEmpty()) {
            return IdentityMatch.UNKNOWN;
        }

        for (String token : componentTokens) {
            if (token.equals(cpeProduct)) {
                return IdentityMatch.MATCH;
            }
            if (foldIdentityToken(token).equals(foldedCpeProduct)) {
                return IdentityMatch.MATCH;
            }
        }

        return IdentityMatch.UNKNOWN;
    }

    private LinkedHashSet<String> componentIdentityTokens(InventoryComponent component) {
        LinkedHashSet<String> tokens = new LinkedHashSet<>();
        if (component == null) {
            return tokens;
        }

        collectIdentityTokens(tokens, component.getPackageName());
        collectIdentityTokens(tokens, component.getNormalizedName());

        PurlUtil.ParsedPurl parsedPurl = PurlUtil.parse(component.getPurl());
        collectIdentityTokens(tokens, parsedPurl.packageName());
        collectIdentityTokens(tokens, parsedPurl.namespace());

        return tokens;
    }

    private void collectIdentityTokens(LinkedHashSet<String> sink, String raw) {
        String normalized = IdentityUtil.normalize(raw);
        if (normalized.isBlank() || "unknown".equals(normalized)) {
            return;
        }
        sink.add(normalized);
        for (String token : normalized.split("[/:]")) {
            String item = IdentityUtil.normalize(token);
            if (!item.isBlank() && !"unknown".equals(item)) {
                sink.add(item);
            }
        }
    }

    private String foldIdentityToken(String value) {
        String normalized = IdentityUtil.normalize(value);
        if (normalized.isBlank()) {
            return "";
        }
        return normalized.replace("-", "")
                .replace("_", "")
                .replace(".", "");
    }

    private String textOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText("");
        return value.isBlank() ? null : value.trim();
    }

    private JsonNode parseJson(String exprJson) {
        if (exprJson == null || exprJson.isBlank()) {
            return null;
        }
        try {
            return objectMapper.readTree(exprJson);
        } catch (Exception e) {
            return null;
        }
    }

    private String normalizeOperator(String operator) {
        if (operator == null || operator.isBlank()) {
            return "OR";
        }
        String normalized = operator.trim().toUpperCase(Locale.ROOT);
        return "AND".equals(normalized) ? "AND" : "OR";
    }

    private boolean wildcard(String value) {
        if (value == null || value.isBlank()) {
            return true;
        }
        return "*".equals(value) || "-".equals(value);
    }

    private TriState combine(String operator, List<TriState> operands) {
        if (operands == null || operands.isEmpty()) {
            return TriState.UNKNOWN;
        }
        if ("AND".equals(operator)) {
            TriState result = TriState.TRUE;
            for (TriState operand : operands) {
                if (operand == TriState.FALSE) {
                    return TriState.FALSE;
                }
                if (operand == TriState.UNKNOWN) {
                    result = TriState.UNKNOWN;
                }
            }
            return result;
        }
        TriState result = TriState.FALSE;
        for (TriState operand : operands) {
            if (operand == TriState.TRUE) {
                return TriState.TRUE;
            }
            if (operand == TriState.UNKNOWN) {
                result = TriState.UNKNOWN;
            }
        }
        return result;
    }

    private TriState or(TriState left, TriState right) {
        if (left == TriState.TRUE || right == TriState.TRUE) {
            return TriState.TRUE;
        }
        if (left == TriState.UNKNOWN || right == TriState.UNKNOWN) {
            return TriState.UNKNOWN;
        }
        return TriState.FALSE;
    }

    private TriState negate(TriState value) {
        return switch (value) {
            case TRUE -> TriState.FALSE;
            case FALSE -> TriState.TRUE;
            case UNKNOWN -> TriState.UNKNOWN;
        };
    }

    private enum TriState {
        TRUE,
        FALSE,
        UNKNOWN
    }

    private enum IdentityMatch {
        MATCH,
        UNKNOWN
    }

    // BLG-005: detect ecosystem-specific version scheme from the component PURL so that
    // Debian (epoch:upstream-revision), RPM (tilde/caret), and Python (PEP 440) versions
    // are compared correctly instead of falling through to the generic UNKNOWN comparator.
    private VersionScheme schemeForComponent(InventoryComponent component) {
        if (component == null) {
            return VersionScheme.UNKNOWN;
        }
        String purl = component.getPurl();
        if (purl != null && !purl.isBlank()) {
            PurlUtil.ParsedPurl parsed = PurlUtil.parse(purl);
            VersionScheme fromPurl = schemeForEcosystem(parsed.ecosystem());
            if (fromPurl != VersionScheme.UNKNOWN) {
                return fromPurl;
            }
        }
        return VersionScheme.UNKNOWN;
    }

    private VersionScheme schemeForEcosystem(String ecosystem) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return VersionScheme.UNKNOWN;
        }
        return switch (ecosystem.toLowerCase(Locale.ROOT)) {
            case "deb", "debian" -> VersionScheme.DPKG;
            case "rpm" -> VersionScheme.RPM;
            case "pypi" -> VersionScheme.PEP440;
            case "maven" -> VersionScheme.MAVEN;
            default -> VersionScheme.UNKNOWN;
        };
    }
}
