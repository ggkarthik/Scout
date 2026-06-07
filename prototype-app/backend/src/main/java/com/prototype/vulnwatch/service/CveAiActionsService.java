package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.client.http.OpenAiClient.AiCallOptions;
import com.prototype.vulnwatch.controller.CveDetailController;
import java.time.Instant;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class CveAiActionsService {

    private static final Logger LOG = LoggerFactory.getLogger(CveAiActionsService.class);

    private static final String SYSTEM_PROMPT = """
            You are a senior vulnerability analyst advisor. Given the full operational context of a CVE
            (investigation status, assessment, findings, EOL components, SLA timers, exploit signals,
            impacted assets, and remediation progress), identify the TOP 3 most critical actions the
            security analyst must take RIGHT NOW — ranked by urgency.

            Rules:
            - Each action must be specific, actionable, and directly address a gap visible in the context.
            - Urgency: IMMEDIATE (within 24h), SHORT_TERM (1-7 days), MEDIUM_TERM (7-30 days).
            - action_type must be one of: START_INVESTIGATION, ESCALATE, CREATE_FINDINGS, PATCH,
              NOTIFY_LEADERSHIP, NOTIFY_REMEDIATION, COMPENSATING_CONTROL, CLOSE_INVESTIGATION,
              ASSESS_APPLICABILITY, EOL_MIGRATION, VALIDATE_FINDINGS.
            - rationale must cite specific numbers, dates, or states from the context (e.g. "47 unpatched
              assets", "KEV due 2024-03-05", "EPSS 97.3%", "investigation IN_PROGRESS for 14 days").
            - If findings are only partially created (open_findings < impacted_assets), always include
              a CREATE_FINDINGS action until all assets are covered.
            - If CISA KEV due date is within 7 days, always include a NOTIFY_REMEDIATION action.
            - If severity is CRITICAL or HIGH and leadership has not been notified, include NOTIFY_LEADERSHIP.
            - Never repeat or include a generic action if the context shows it is already complete.

            Respond with valid JSON only (no markdown fences):
            {
              "actions": [
                {
                  "priority": 1,
                  "urgency": "IMMEDIATE",
                  "urgency_color": "red",
                  "title": "<specific concise action title>",
                  "rationale": "<1-2 sentences citing specific context values>",
                  "action_type": "<one of the valid types above>",
                  "timeframe": "<e.g. Within 24 hours>",
                  "owner": "<e.g. Security Analyst / Patch Management / CISO>"
                }
              ],
              "context_summary": "<1 sentence: key risk factors considered>"
            }
            """;

    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper;
    private final CveAiSolutionPersistenceService aiSolutionPersistenceService;

    public CveAiActionsService(
            OpenAiClient openAiClient,
            ObjectMapper objectMapper,
            CveAiSolutionPersistenceService aiSolutionPersistenceService
    ) {
        this.openAiClient = openAiClient;
        this.objectMapper = objectMapper;
        this.aiSolutionPersistenceService = aiSolutionPersistenceService;
    }

    public CveDetailController.AiActionsResponse generate(String cveId, Map<String, Object> context) {
        if (!openAiClient.isAvailable()) {
            CveDetailController.AiActionsResponse response = new CveDetailController.AiActionsResponse();
            response.success = false;
            response.error = "OpenAI is not configured.";
            return response;
        }

        String userPrompt = "CVE operational context:\n" + toJson(context);
        String raw = openAiClient.chat(SYSTEM_PROMPT, userPrompt, new AiCallOptions(null, 0.3, 1200, true));
        if (raw == null || raw.isBlank()) {
            CveDetailController.AiActionsResponse response = new CveDetailController.AiActionsResponse();
            response.success = false;
            response.error = "AI action generation failed.";
            return response;
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(raw, Map.class);
            try {
                aiSolutionPersistenceService.saveAiActions(cveId, raw);
            } catch (Exception saveError) {
                LOG.warn("Failed to persist AI actions for {}: {}", cveId, saveError.getMessage());
            }
            CveDetailController.AiActionsResponse response = new CveDetailController.AiActionsResponse();
            response.success = true;
            response.data = parsed;
            response.generatedAt = Instant.now();
            return response;
        } catch (Exception e) {
            CveDetailController.AiActionsResponse response = new CveDetailController.AiActionsResponse();
            response.success = false;
            response.error = "Failed to parse AI response: " + e.getMessage();
            return response;
        }
    }

    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }
}
