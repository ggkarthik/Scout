package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Vulnerability;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;

/**
 * Evaluates the tenant's findingsScoreConfig rules against a finding and returns
 * a score in the range 0–10.
 *
 * <p>The config is a JSON array of column rules:
 * <pre>
 * [
 *   {
 *     "table": "VULNERABILITY",
 *     "column": "severity",
 *     "values": [
 *       { "operator": "is", "value": "CRITICAL", "weight": 0.4 },
 *       { "operator": "is", "value": "HIGH",     "weight": 0.2 }
 *     ]
 *   },
 *   ...
 * ]
 * </pre>
 *
 * <p>For each column rule the service takes the highest matching value weight,
 * then sums across all columns (max possible sum = 1.0) and scales to 0–10.
 */
@Service
public class FindingsScoreService {

    private final ObjectMapper objectMapper;

    public FindingsScoreService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public double compute(String findingsScoreConfig, Finding finding) {
        List<ColumnRule> rules = parseRules(findingsScoreConfig);
        if (rules == null) {
            return 0.0;
        }
        Map<String, Object> attrs = extractAttributes(finding);
        return applyRules(rules, attrs);
    }

    /**
     * Compute findings score without requiring a persisted {@link Finding} object.
     * Used during finding creation and recompute flows where the entity may not
     * yet exist.
     */
    public double computeFromParts(String findingsScoreConfig,
                                   Vulnerability vuln,
                                   Asset asset,
                                   InventoryComponent comp,
                                   String severityOverride) {
        List<ColumnRule> rules = parseRules(findingsScoreConfig);
        if (rules == null) {
            return 0.0;
        }
        Map<String, Object> attrs = extractAttributesFromParts(vuln, asset, comp, severityOverride);
        return applyRules(rules, attrs);
    }

    private List<ColumnRule> parseRules(String findingsScoreConfig) {
        if (findingsScoreConfig == null || findingsScoreConfig.isBlank()) {
            return null;
        }
        String trimmed = findingsScoreConfig.trim();
        if ("[]".equals(trimmed) || "null".equals(trimmed)) {
            return null;
        }
        try {
            List<ColumnRule> rules = objectMapper.readValue(findingsScoreConfig, new TypeReference<>() {});
            return (rules == null || rules.isEmpty()) ? null : rules;
        } catch (Exception ignored) {
            return null;
        }
    }

    private double applyRules(List<ColumnRule> rules, Map<String, Object> attrs) {
        double totalWeight = 0.0;
        for (ColumnRule rule : rules) {
            if (rule.table() == null || rule.column() == null
                    || rule.values() == null || rule.values().isEmpty()) {
                continue;
            }
            String attrKey = rule.table() + "." + rule.column();
            Object attrValue = attrs.get(attrKey);

            double maxMatchWeight = 0.0;
            for (ValueCondition vc : rule.values()) {
                if (vc.operator() == null || vc.value() == null) {
                    continue;
                }
                boolean firstMatches = evaluateCondition(vc.operator(), vc.value(), attrValue);
                boolean secondMatches = (vc.operator2() == null || vc.value2() == null || vc.value2().isBlank())
                        || evaluateCondition(vc.operator2(), vc.value2(), attrValue);
                if (firstMatches && secondMatches) {
                    maxMatchWeight = Math.max(maxMatchWeight, vc.weight());
                }
            }
            totalWeight += maxMatchWeight;
        }
        // totalWeight is in 0–1 range (user weights sum to 1); scale to 0–10
        return Math.min(10.0, Math.max(0.0, totalWeight * 10.0));
    }

    private Map<String, Object> extractAttributes(Finding finding) {
        return extractAttributesFromParts(
                finding.getVulnerability(),
                finding.getAsset(),
                finding.getComponent(),
                finding.getSeverityOverride()
        );
    }

    private Map<String, Object> extractAttributesFromParts(
            Vulnerability vuln, Asset asset, InventoryComponent comp, String severityOverride) {

        String effectiveSeverity = severityOverride != null
                ? severityOverride
                : (vuln.getSeverity() != null ? vuln.getSeverity() : "UNKNOWN");

        Integer eolDaysRemaining = comp.getEolDate() != null
                ? (int) ChronoUnit.DAYS.between(LocalDate.now(), comp.getEolDate())
                : null;

        Map<String, Object> attrs = new LinkedHashMap<>();

        // ── VULNERABILITY columns — keys match the UI column dropdown values ───
        attrs.put("VULNERABILITY.severity", effectiveSeverity);
        attrs.put("VULNERABILITY.cvssScore", vuln.getCvssScore());
        attrs.put("VULNERABILITY.epssScore", vuln.getEpssScore());
        attrs.put("VULNERABILITY.isInKev", vuln.isInKev());
        // exploitExists: no dedicated field; treat as equivalent to KEV membership
        attrs.put("VULNERABILITY.exploitExists", vuln.isInKev());
        attrs.put("VULNERABILITY.attackVector", vuln.getAttackVector());
        attrs.put("VULNERABILITY.attackComplexity", vuln.getAttackComplexity());
        attrs.put("VULNERABILITY.privilegesRequired", vuln.getPrivilegesRequired());
        attrs.put("VULNERABILITY.userInteraction", vuln.getUserInteraction());
        attrs.put("VULNERABILITY.scope", vuln.getScope());
        attrs.put("VULNERABILITY.vulnStatus", vuln.getVulnStatus());

        // ── ASSET columns ──────────────────────────────────────────────────────
        attrs.put("ASSET.businessCriticality",
                asset.getBusinessCriticality() != null ? asset.getBusinessCriticality().name() : null);
        attrs.put("ASSET.environment", asset.getEnvironment());
        attrs.put("ASSET.assetType", asset.getType() != null ? asset.getType().name() : null);
        attrs.put("ASSET.status", asset.getState() != null ? asset.getState().name() : null);
        attrs.put("ASSET.owner", asset.getOwnerTeam());
        attrs.put("ASSET.region", asset.getCloudRegion());
        attrs.put("ASSET.cloudProvider", asset.getCloudProvider());

        // ── SOFTWARE columns ───────────────────────────────────────────────────
        attrs.put("SOFTWARE.name", comp.getPackageName());
        attrs.put("SOFTWARE.version", comp.getVersion());
        attrs.put("SOFTWARE.language", comp.getEcosystem());
        attrs.put("SOFTWARE.packageType", comp.getEcosystem());
        attrs.put("SOFTWARE.isEol", comp.getIsEol());
        attrs.put("SOFTWARE.purl", comp.getPurl());
        // vendor = namespace segment of purl (e.g. "oracle" from pkg:generic/oracle/database_server)
        // falls back to ecosystem when purl has no namespace
        String purlVendor = extractVendorFromPurl(comp.getPurl());
        attrs.put("SOFTWARE.vendor", purlVendor != null ? purlVendor : comp.getEcosystem());

        return attrs;
    }

    private String extractVendorFromPurl(String purl) {
        if (purl == null || purl.isBlank()) return null;
        // purl format: pkg:type/namespace/name@version
        String withoutScheme = purl.startsWith("pkg:") ? purl.substring(4) : purl;
        int firstSlash = withoutScheme.indexOf('/');
        if (firstSlash < 0) return null;
        String afterType = withoutScheme.substring(firstSlash + 1);
        int secondSlash = afterType.indexOf('/');
        if (secondSlash < 0) return null; // no namespace segment
        return afterType.substring(0, secondSlash);
    }

    private boolean evaluateCondition(String operator, String ruleValue, Object attrValue) {
        if (attrValue == null) {
            return false;
        }
        String op = operator.trim().toLowerCase(Locale.ROOT);
        String attrStr = String.valueOf(attrValue).trim();
        String ruleStr = ruleValue.trim();

        return switch (op) {
            case ">", "<", ">=", "<=", "=", "!=" -> {
                double numAttr;
                double numRule;
                try {
                    numAttr = Double.parseDouble(attrStr);
                    numRule = Double.parseDouble(ruleStr);
                } catch (NumberFormatException e) {
                    // Non-numeric value — fall back to string equality for = and !=
                    if (op.equals("=")) yield attrStr.equalsIgnoreCase(ruleStr);
                    if (op.equals("!=")) yield !attrStr.equalsIgnoreCase(ruleStr);
                    yield false;
                }
                yield switch (op) {
                    case ">" -> numAttr > numRule;
                    case "<" -> numAttr < numRule;
                    case ">=" -> numAttr >= numRule;
                    case "<=" -> numAttr <= numRule;
                    case "=" -> Double.compare(numAttr, numRule) == 0;
                    case "!=" -> Double.compare(numAttr, numRule) != 0;
                    default -> false;
                };
            }
            case "contains" ->
                    attrStr.toLowerCase(Locale.ROOT).contains(ruleStr.toLowerCase(Locale.ROOT));
            case "not contains" ->
                    !attrStr.toLowerCase(Locale.ROOT).contains(ruleStr.toLowerCase(Locale.ROOT));
            case "exact match", "is" -> attrStr.equalsIgnoreCase(ruleStr);
            case "is not" -> !attrStr.equalsIgnoreCase(ruleStr);
            default -> false;
        };
    }

    /**
     * Evaluates suppression-rule conditions (table/column/operator/value, no weight) against a
     * finding. The conditionLogic ("AND"/"OR") controls how multiple conditions are combined.
     */
    public boolean matchesSuppressionConditions(
            String conditionsJson, String conditionLogic, Finding finding) {
        if (conditionsJson == null || conditionsJson.isBlank()) {
            return false;
        }
        List<java.util.Map<String, Object>> conditions;
        try {
            conditions = objectMapper.readValue(conditionsJson, new TypeReference<>() {});
        } catch (Exception ignored) {
            return false;
        }
        if (conditions == null || conditions.isEmpty()) {
            return false;
        }
        Map<String, Object> attrs = extractAttributes(finding);
        boolean isAnd = !"OR".equalsIgnoreCase(conditionLogic);
        for (java.util.Map<String, Object> cond : conditions) {
            String table    = (String) cond.get("table");
            String column   = (String) cond.get("column");
            String operator = (String) cond.get("operator");
            String value    = cond.get("value") != null ? cond.get("value").toString() : null;
            if (table == null || column == null || operator == null || value == null) continue;
            Object attrValue = attrs.get(table + "." + column);
            boolean matches = evaluateCondition(operator, value, attrValue);
            if (isAnd && !matches) return false;
            if (!isAnd && matches) return true;
        }
        return isAnd;
    }

    public record ColumnRule(String table, String column, List<ValueCondition> values) {}

    /**
     * A single value-weight condition. When {@code operator2} and {@code value2} are both
     * non-blank the two bounds are AND-ed (range condition), e.g. {@code >= 6 AND <= 8}.
     */
    /**
     * Evaluates suppression-rule conditions against an OrgCveRecord.
     * For SOFTWARE table conditions, packageNames is checked — the condition
     * matches if ANY package name in the list satisfies the condition.
     */
    public boolean matchesCveSuppressionConditions(
            String conditionsJson, String conditionLogic, OrgCveRecord record, List<String> packageNames) {
        if (conditionsJson == null || conditionsJson.isBlank()) return false;
        List<java.util.Map<String, Object>> conditions;
        try {
            conditions = objectMapper.readValue(conditionsJson, new TypeReference<>() {});
        } catch (Exception e) {
            return false;
        }
        if (conditions.isEmpty()) return false;

        Map<String, Object> attrs = new LinkedHashMap<>();
        attrs.put("VULNERABILITY.severity", record.getSeverity());
        attrs.put("VULNERABILITY.cvssScore", record.getCvssScore());
        attrs.put("VULNERABILITY.epssScore", record.getEpssScore());
        attrs.put("VULNERABILITY.isInKev", record.isInKev());
        attrs.put("VULNERABILITY.exploitExists", record.isInKev());
        if (record.getVulnerability() != null) {
            Vulnerability v = record.getVulnerability();
            attrs.put("VULNERABILITY.attackVector", v.getAttackVector());
            attrs.put("VULNERABILITY.attackComplexity", v.getAttackComplexity());
            attrs.put("VULNERABILITY.privilegesRequired", v.getPrivilegesRequired());
            attrs.put("VULNERABILITY.userInteraction", v.getUserInteraction());
            attrs.put("VULNERABILITY.scope", v.getScope());
            attrs.put("VULNERABILITY.vulnStatus", v.getVulnStatus());
        }

        boolean isAnd = !"OR".equalsIgnoreCase(conditionLogic);
        for (Map<String, Object> cond : conditions) {
            String table    = String.valueOf(cond.getOrDefault("table", "")).toUpperCase(Locale.ROOT);
            String column   = String.valueOf(cond.getOrDefault("column", ""));
            String operator = String.valueOf(cond.getOrDefault("operator", ""));
            String value    = String.valueOf(cond.getOrDefault("value", ""));

            boolean matches;
            if ("SOFTWARE".equals(table)) {
                // For SOFTWARE conditions on CVE records, check if any matched package satisfies
                if ("name".equalsIgnoreCase(column) && packageNames != null && !packageNames.isEmpty()) {
                    final String op = operator;
                    final String val = value;
                    matches = packageNames.stream().anyMatch(p -> evaluateCondition(op, val, p));
                } else {
                    matches = false;
                }
            } else {
                Object attrValue = attrs.get(table + "." + column);
                matches = evaluateCondition(operator, value, attrValue);
            }

            if (isAnd && !matches) return false;
            if (!isAnd && matches) return true;
        }
        return isAnd;
    }

    public record ValueCondition(
            String operator, String value,
            String operator2, String value2,
            double weight
    ) {}
}
