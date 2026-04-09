package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

@Service
public class CveInvestigationAiSummaryService {

    private static final Logger LOG = LoggerFactory.getLogger(CveInvestigationAiSummaryService.class);
    private static final String SYSTEM_PROMPT = """
            You generate CVE investigation summaries for a vulnerability operations workbench.
            Use only the provided evidence. Do not invent assets, versions, timelines, owners, or counts.
            Return only JSON that matches the requested schema exactly.
            Keep remediation actionable and prioritized.
            """;

    private final CveInvestigationSummaryService deterministicSummaryService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final Environment environment;

    @Value("${app.openai.base-url:https://api.openai.com/v1}")
    private String openAiBaseUrl;

    @Value("${app.openai.model:gpt-5-mini}")
    private String openAiModel;

    @Value("${app.openai.min-request-interval-ms:0}")
    private long minRequestIntervalMs;

    @Value("${app.openai.max-retries:2}")
    private int maxRetries;

    @Value("${app.openai.retry-base-backoff-ms:1500}")
    private long retryBaseBackoffMs;

    @Value("${app.openai.max-output-tokens:1800}")
    private int maxOutputTokens;

    public CveInvestigationAiSummaryService(
            CveInvestigationSummaryService deterministicSummaryService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            Environment environment
    ) {
        this.deterministicSummaryService = deterministicSummaryService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.environment = environment;
    }

    public CveInvestigationSummaryResponse generateAiSummary(
            String cveId,
            Map<String, Object> payload
    ) {
        String apiKey = resolveApiKey();
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("OpenAI API key is not configured. Set OPENAI_API_KEY or openai_API_KEY.");
        }

        CveInvestigationSummaryResponse deterministicSummary = deterministicSummaryService.generateSummary(cveId, payload);
        String requestBody = buildRequestBody(cveId, payload, deterministicSummary);
        String rawResponse = executeOpenAiRequest(apiKey, requestBody);
        String summaryJson = extractSummaryJson(rawResponse);
        return mergeWithDeterministicFallback(cveId, deterministicSummary, summaryJson);
    }

    private String resolveApiKey() {
        for (String key : List.of("app.openai.api-key", "OPENAI_API_KEY", "openai_API_KEY", "openai.api.key")) {
            String value = environment.getProperty(key);
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private String buildRequestBody(
            String cveId,
            Map<String, Object> payload,
            CveInvestigationSummaryResponse deterministicSummary
    ) {
        try {
            Map<String, Object> schema = responseSchema();
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("model", openAiModel);
            request.put("max_output_tokens", maxOutputTokens);
            request.put("input", List.of(
                    Map.of(
                            "role", "system",
                            "content", List.of(Map.of("type", "input_text", "text", SYSTEM_PROMPT))
                    ),
                    Map.of(
                            "role", "user",
                            "content", List.of(Map.of("type", "input_text", "text", buildUserPrompt(cveId, payload, deterministicSummary)))
                    )
            ));
            request.put("text", Map.of(
                    "format", Map.of(
                            "type", "json_schema",
                            "name", "cve_investigation_summary",
                            "strict", true,
                            "schema", schema
                    )
            ));
            return objectMapper.writeValueAsString(request);
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Unable to build OpenAI summary request.", error);
        }
    }

    private String buildUserPrompt(
            String cveId,
            Map<String, Object> payload,
            CveInvestigationSummaryResponse deterministicSummary
    ) throws JsonProcessingException {
        return """
                Build an AI-authored CVE investigation narrative for %s.

                Requirements:
                - Preserve all numeric counts exactly.
                - The output must remain factual and bounded to the supplied evidence.
                - Rewrite only the narrative text fields.
                - Do not change metrics, scores, priorities, owners, timeframes, or action types.
                - If evidence is missing, say so plainly rather than inferring.
                - Keep remediation titles concise and imperative.

                Investigation payload:
                %s

                Deterministic baseline summary:
                %s
                """.formatted(
                cveId,
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(payload),
                objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(deterministicSummary)
        );
    }

    private String executeOpenAiRequest(String apiKey, String requestBody) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setBearerAuth(apiKey);

        return outboundHttpClient.execute(
                openAiBaseUrl + "/responses",
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers),
                String.class,
                "OpenAI investigation summary",
                outboundPolicy(),
                this::classifyFailure,
                response -> {
                    String body = response.getBody();
                    if (body == null || body.isBlank()) {
                        throw new IllegalStateException("OpenAI response body is empty.");
                    }
                    return body;
                }
        );
    }

    private String extractSummaryJson(String rawResponse) {
        try {
            JsonNode root = objectMapper.readTree(rawResponse);
            JsonNode parsed = root.path("output_parsed");
            if (parsed != null && !parsed.isMissingNode() && !parsed.isNull()) {
                return objectMapper.writeValueAsString(parsed);
            }
            JsonNode direct = root.path("output_text");
            if (direct.isTextual() && !direct.asText().isBlank()) {
                return sanitizeJsonBlock(direct.asText());
            }
            if (direct.isObject() || direct.isArray()) {
                return objectMapper.writeValueAsString(direct);
            }
            String nested = findOutputText(root.path("output"));
            if (nested != null && !nested.isBlank()) {
                return sanitizeJsonBlock(nested);
            }
            throw new IllegalStateException("OpenAI response did not contain summary text.");
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("OpenAI response was not valid JSON.", error);
        }
    }

    private String findOutputText(JsonNode outputNode) {
        if (outputNode == null || outputNode.isMissingNode() || outputNode.isNull()) {
            return null;
        }
        if (outputNode.isTextual()) {
            return outputNode.asText();
        }
        if (outputNode.isArray()) {
            for (JsonNode item : outputNode) {
                String match = findOutputText(item);
                if (match != null && !match.isBlank()) {
                    return match;
                }
            }
            return null;
        }
        JsonNode textNode = outputNode.get("text");
        if (textNode != null) {
            if (textNode.isTextual()) {
                return textNode.asText();
            }
            JsonNode valueNode = textNode.get("value");
            if (valueNode != null && valueNode.isTextual()) {
                return valueNode.asText();
            }
        }
        JsonNode argumentsNode = outputNode.get("arguments");
        if (argumentsNode != null) {
            if (argumentsNode.isTextual()) {
                return argumentsNode.asText();
            }
            if (argumentsNode.isObject() || argumentsNode.isArray()) {
                try {
                    return objectMapper.writeValueAsString(argumentsNode);
                } catch (JsonProcessingException ignored) {
                    // fall through
                }
            }
        }
        JsonNode jsonNode = outputNode.get("json");
        if (jsonNode != null && (jsonNode.isObject() || jsonNode.isArray())) {
            try {
                return objectMapper.writeValueAsString(jsonNode);
            } catch (JsonProcessingException ignored) {
                // fall through
            }
        }
        for (String field : List.of("content", "output", "message", "parsed")) {
            String match = findOutputText(outputNode.get(field));
            if (match != null && !match.isBlank()) {
                return match;
            }
        }
        return null;
    }

    private String sanitizeJsonBlock(String value) {
        String trimmed = value.trim();
        if (trimmed.startsWith("```")) {
            int firstLineBreak = trimmed.indexOf('\n');
            int lastFence = trimmed.lastIndexOf("```");
            if (firstLineBreak >= 0 && lastFence > firstLineBreak) {
                return trimmed.substring(firstLineBreak + 1, lastFence).trim();
            }
        }
        return trimmed;
    }

    private CveInvestigationSummaryResponse normalizeGeneratedAt(CveInvestigationSummaryResponse summary) {
        if (summary.generatedAt() != null) {
            return summary;
        }
        return new CveInvestigationSummaryResponse(
                Instant.now(),
                summary.executiveSummary(),
                summary.riskAnalysis(),
                summary.impactAnalysis(),
                summary.remediationPlan(),
                summary.keyFindings(),
                summary.metrics()
        );
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("openai", minRequestIntervalMs, maxRetries, retryBaseBackoffMs);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(OutboundFailureContext context) {
        RuntimeException exception = new IllegalStateException("OpenAI summary request failed: " + context.error().getMessage(), context.error());
        if (context.isRetryableByDefault()) {
            return OutboundFailureDecision.retry(context.retryAfterDelayMs(), exception);
        }
        return OutboundFailureDecision.fail(exception);
    }

    private Map<String, Object> responseSchema() {
        Map<String, Object> remediationAction = objectSchema(Map.of(
                "priority", integerSchema(),
                "title", stringSchema(),
                "detail", stringSchema()
        ));

        return objectSchema(Map.of(
                "executiveSummary", stringSchema(),
                "riskRationale", stringSchema(),
                "falsePositiveSummary", stringSchema(),
                "eolRiskSummary", stringSchema(),
                "patchGapSummary", stringSchema(),
                "remediationPlan", arraySchema(remediationAction),
                "keyFindings", arraySchema(stringSchema())
        ));
    }

    private CveInvestigationSummaryResponse mergeWithDeterministicFallback(
            String cveId,
            CveInvestigationSummaryResponse deterministicSummary,
            String summaryJson
    ) {
        try {
            JsonNode root = objectMapper.readTree(summaryJson);
            String executiveSummary = textOrDefault(root.get("executiveSummary"), deterministicSummary.executiveSummary());
            String riskRationale = textOrDefault(root.get("riskRationale"), deterministicSummary.riskAnalysis().rationale());
            String falsePositiveSummary = textOrDefault(
                    root.get("falsePositiveSummary"),
                    deterministicSummary.impactAnalysis().falsePositiveSummary()
            );
            String eolRiskSummary = textOrDefault(
                    root.get("eolRiskSummary"),
                    deterministicSummary.impactAnalysis().eolRiskSummary()
            );
            String patchGapSummary = textOrDefault(
                    root.get("patchGapSummary"),
                    deterministicSummary.impactAnalysis().patchGapSummary()
            );

            List<String> keyFindings = extractStringList(root.get("keyFindings"));
            if (keyFindings.isEmpty()) {
                keyFindings = deterministicSummary.keyFindings();
            }

            List<CveInvestigationSummaryResponse.RemediationAction> remediationPlan =
                    mergeRemediationPlan(root.get("remediationPlan"), deterministicSummary.remediationPlan());

            return new CveInvestigationSummaryResponse(
                    Instant.now(),
                    executiveSummary,
                    new CveInvestigationSummaryResponse.RiskAnalysis(
                            deterministicSummary.riskAnalysis().level(),
                            deterministicSummary.riskAnalysis().score(),
                            riskRationale
                    ),
                    new CveInvestigationSummaryResponse.ImpactAnalysis(
                            deterministicSummary.impactAnalysis().externalFacingCount(),
                            deterministicSummary.impactAnalysis().internalAssetCount(),
                            falsePositiveSummary,
                            eolRiskSummary,
                            patchGapSummary
                    ),
                    remediationPlan,
                    keyFindings,
                    deterministicSummary.metrics()
            );
        } catch (Exception error) {
            LOG.warn(
                    "OpenAI summary parse failed for {}: payload={} error={}. Falling back to deterministic summary.",
                    cveId,
                    abbreviate(summaryJson),
                    error.getMessage()
            );
            return normalizeGeneratedAt(deterministicSummary);
        }
    }

    private List<CveInvestigationSummaryResponse.RemediationAction> mergeRemediationPlan(
            JsonNode remediationNode,
            List<CveInvestigationSummaryResponse.RemediationAction> deterministicPlan
    ) {
        if (remediationNode == null || !remediationNode.isArray()) {
            return deterministicPlan;
        }
        Map<Integer, JsonNode> aiByPriority = new LinkedHashMap<>();
        for (JsonNode item : remediationNode) {
            JsonNode priorityNode = item.get("priority");
            if (priorityNode != null && priorityNode.canConvertToInt()) {
                aiByPriority.put(priorityNode.asInt(), item);
            }
        }
        return deterministicPlan.stream().map(action -> {
            JsonNode aiAction = aiByPriority.get(action.priority());
            if (aiAction == null || aiAction.isMissingNode()) {
                return action;
            }
            return new CveInvestigationSummaryResponse.RemediationAction(
                    action.priority(),
                    action.priorityLabel(),
                    textOrDefault(aiAction.get("title"), action.title()),
                    textOrDefault(aiAction.get("detail"), action.detail()),
                    action.owner(),
                    action.timeframe(),
                    action.type()
            );
        }).toList();
    }

    private List<String> extractStringList(JsonNode node) {
        if (node == null || !node.isArray()) {
            return List.of();
        }
        return java.util.stream.StreamSupport.stream(node.spliterator(), false)
                .filter(JsonNode::isTextual)
                .map(JsonNode::asText)
                .filter(value -> value != null && !value.isBlank())
                .toList();
    }

    private String textOrDefault(JsonNode node, String fallback) {
        if (node != null && node.isTextual() && !node.asText().isBlank()) {
            return node.asText();
        }
        return fallback;
    }

    private Map<String, Object> objectSchema(Map<String, Object> properties) {
        return new LinkedHashMap<>(Map.of(
                "type", "object",
                "properties", properties,
                "required", properties.keySet(),
                "additionalProperties", false
        ));
    }

    private Map<String, Object> arraySchema(Object items) {
        return new LinkedHashMap<>(Map.of(
                "type", "array",
                "items", items
        ));
    }

    private Map<String, Object> stringSchema() {
        return new LinkedHashMap<>(Map.of("type", "string"));
    }

    private Map<String, Object> integerSchema() {
        return new LinkedHashMap<>(Map.of("type", "integer"));
    }

    private String abbreviate(String value) {
        if (value == null) {
            return "null";
        }
        if (value.length() <= 2000) {
            return value;
        }
        return value.substring(0, 2000) + "...";
    }
}
