package com.prototype.vulnwatch.aisecurity.policy;

import com.fasterxml.jackson.databind.JsonNode;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Iterator;
import java.util.Map;
import org.springframework.stereotype.Component;

/** Bounded, data-only policy predicate evaluator. */
@Component
public class AiGridPredicateEngine {

    static final int MAX_DEPTH = 8;
    static final int MAX_NODES = 100;

    public boolean evaluate(JsonNode predicate, Map<String, JsonNode> facts) {
        return evaluate(predicate, facts, Map.of());
    }

    public boolean evaluate(JsonNode predicate, Map<String, JsonNode> facts, Map<String, Object> parameters) {
        Counter counter = new Counter();
        return evaluate(predicate, facts, parameters, 1, counter);
    }

    public void validate(JsonNode predicate) {
        evaluate(predicate, Map.of(), Map.of(), 1, new Counter(), true);
    }

    private boolean evaluate(JsonNode node, Map<String, JsonNode> facts, Map<String, Object> parameters, int depth, Counter counter) {
        return evaluate(node, facts, parameters, depth, counter, false);
    }

    private boolean evaluate(JsonNode node, Map<String, JsonNode> facts, Map<String, Object> parameters, int depth, Counter counter, boolean validationOnly) {
        if (node == null || !node.isObject() || depth > MAX_DEPTH || ++counter.nodes > MAX_NODES) {
            throw new IllegalArgumentException("Invalid or unbounded AI Grid predicate");
        }
        if (node.has("all") || node.has("any")) {
            String operator = node.has("all") ? "all" : "any";
            ensureOnly(node, operator);
            JsonNode children = node.get(operator);
            if (!children.isArray() || children.isEmpty()) {
                throw new IllegalArgumentException(operator + " requires a non-empty array");
            }
            boolean result = "all".equals(operator);
            for (JsonNode child : children) {
                boolean childResult = evaluate(child, facts, parameters, depth + 1, counter, validationOnly);
                result = "all".equals(operator) ? result && childResult : result || childResult;
            }
            return result;
        }
        if (node.has("not")) {
            ensureOnly(node, "not");
            return !evaluate(node.get("not"), facts, parameters, depth + 1, counter, validationOnly);
        }
        if (!node.hasNonNull("fact") || !node.get("fact").isTextual()) {
            throw new IllegalArgumentException("Leaf predicate requires a fact key");
        }
        String factKey = node.get("fact").asText();
        JsonNode value = facts.get(factKey);
        String operator = leafOperator(node);
        if (validationOnly) {
            return false;
        }
        if ("exists".equals(operator)) {
            return node.get(operator).asBoolean() == (value != null && !value.isNull());
        }
        if (value == null || value.isNull()) {
            return false;
        }
        JsonNode expected = node.get(operator);
        if (expected != null && expected.isObject() && expected.hasNonNull("parameter")) {
            Object parameter = parameters.get(expected.path("parameter").asText());
            if (parameter == null) throw new IllegalArgumentException("Required policy parameter is not configured");
            expected = new com.fasterxml.jackson.databind.ObjectMapper().valueToTree(parameter);
        }
        return switch (operator) {
            case "eq" -> value.equals(expected);
            case "neq" -> !value.equals(expected);
            case "in" -> contains(expected, value);
            case "gt" -> compare(value, expected) > 0;
            case "gte" -> compare(value, expected) >= 0;
            case "lt" -> compare(value, expected) < 0;
            case "lte" -> compare(value, expected) <= 0;
            case "strength_lt" -> strength(value.asText()) < strength(expected.asText());
            case "empty" -> isEmpty(value) == expected.asBoolean();
            case "non_empty" -> isEmpty(value) != expected.asBoolean();
            case "count_gt" -> count(value) > expected.intValue();
            case "count_gte" -> count(value) >= expected.intValue();
            case "count_lt" -> count(value) < expected.intValue();
            case "count_lte" -> count(value) <= expected.intValue();
            case "count_eq" -> count(value) == expected.intValue();
            case "age_gt_seconds" -> ageSeconds(value) > expected.longValue();
            case "age_gte_seconds" -> ageSeconds(value) >= expected.longValue();
            default -> throw new IllegalArgumentException("Unsupported predicate operator");
        };
    }

    private String leafOperator(JsonNode node) {
        String found = null;
        Iterator<String> fields = node.fieldNames();
        while (fields.hasNext()) {
            String field = fields.next();
            if ("fact".equals(field)) continue;
            if (!java.util.Set.of("exists", "eq", "neq", "in", "gt", "gte", "lt", "lte", "strength_lt",
                    "empty", "non_empty", "count_gt", "count_gte", "count_lt", "count_lte", "count_eq", "age_gt_seconds", "age_gte_seconds").contains(field)
                    || found != null) {
                throw new IllegalArgumentException("Leaf predicate requires exactly one allowed operator");
            }
            found = field;
        }
        if (found == null) throw new IllegalArgumentException("Leaf predicate has no operator");
        if ("in".equals(found) && !node.get(found).isArray() && !parameterReference(node.get(found))) {
            throw new IllegalArgumentException("in requires an array");
        }
        return found;
    }

    private int compare(JsonNode actual, JsonNode expected) {
        if (!actual.isNumber() || !expected.isNumber()) {
            throw new IllegalArgumentException("Ordered comparison requires numeric facts");
        }
        return new BigDecimal(actual.asText()).compareTo(new BigDecimal(expected.asText()));
    }

    private boolean contains(JsonNode values, JsonNode actual) {
        if (!values.isArray()) throw new IllegalArgumentException("in requires an array value");
        for (JsonNode value : values) if (value.equals(actual)) return true;
        return false;
    }
    private boolean parameterReference(JsonNode value) { return value != null && value.isObject() && value.hasNonNull("parameter") && value.size() == 1; }
    private boolean isEmpty(JsonNode value) {
        if (value.isArray() || value.isObject()) return value.isEmpty();
        if (value.isTextual()) return value.asText().isBlank();
        throw new IllegalArgumentException("empty requires a collection or string fact");
    }
    private int count(JsonNode value) {
        if (value.isArray() || value.isObject()) return value.size();
        if (value.isTextual()) return value.asText().length();
        if (value.isIntegralNumber()) return value.intValue();
        throw new IllegalArgumentException("count comparison requires a collection, string, or integral numeric fact");
    }
    private long ageSeconds(JsonNode value) {
        if (!value.isTextual()) throw new IllegalArgumentException("age comparison requires an ISO-8601 timestamp fact");
        try { return Math.max(0, Instant.now().getEpochSecond() - Instant.parse(value.asText()).getEpochSecond()); }
        catch (Exception ex) { throw new IllegalArgumentException("age comparison requires an ISO-8601 timestamp fact", ex); }
    }
    private int strength(String value) { return switch (value == null ? "" : value.toUpperCase()) { case "NONE" -> 0; case "LOW" -> 1; case "MEDIUM" -> 2; case "HIGH" -> 3; default -> -1; }; }

    private void ensureOnly(JsonNode node, String field) {
        if (node.size() != 1 || !node.has(field)) {
            throw new IllegalArgumentException("Logical predicate contains unexpected fields");
        }
    }

    private static final class Counter { private int nodes; }
}
