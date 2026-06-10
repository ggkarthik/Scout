package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.client.http.OpenAiClient.AiCallOptions;
import com.prototype.vulnwatch.dto.AgentRunRequest;
import com.prototype.vulnwatch.dto.AgentRunResponse;
import com.prototype.vulnwatch.dto.AgentTaskMetaDto;
import com.prototype.vulnwatch.dto.AssetCriterionDto;
import com.prototype.vulnwatch.dto.EolAnalysisResponse;
import com.prototype.vulnwatch.dto.FalsePositiveAnalysisResponse;
import com.prototype.vulnwatch.dto.InventoryResolutionResponse;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class InvestigationAgentService {

    private static final Logger log = LoggerFactory.getLogger(InvestigationAgentService.class);

    private static final String SYSTEM_PROMPT =
            "You are a CVE investigation assistant. Assess the supplied investigation data and respond ONLY with valid JSON. "
            + "Use exactly this schema: {\"confidence\":\"HIGH\"|\"MEDIUM\"|\"LOW\",\"reasoning\":\"one or two sentences\"}. "
            + "HIGH = strong evidence from real data; MEDIUM = partial or indirect evidence; LOW = no data or inconclusive.";

    private final InventoryResolutionService inventoryResolutionService;
    private final FalsePositiveAnalysisService falsePositiveAnalysisService;
    private final EolAnalysisService eolAnalysisService;
    private final InvestigationRunbookService runbookService;
    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper;

    public InvestigationAgentService(
            InventoryResolutionService inventoryResolutionService,
            FalsePositiveAnalysisService falsePositiveAnalysisService,
            EolAnalysisService eolAnalysisService,
            InvestigationRunbookService runbookService,
            OpenAiClient openAiClient,
            ObjectMapper objectMapper
    ) {
        this.inventoryResolutionService = inventoryResolutionService;
        this.falsePositiveAnalysisService = falsePositiveAnalysisService;
        this.eolAnalysisService = eolAnalysisService;
        this.runbookService = runbookService;
        this.openAiClient = openAiClient;
        this.objectMapper = objectMapper;
    }

    /**
     * Orchestrates the three Phase 3 analysis services, then uses OpenAI (when
     * available) to produce per-task confidence and reasoning. Falls back to
     * algorithmic confidence derivation when OpenAI is unavailable.
     * Persists task metadata and confidence levels onto the runbook.
     */
    @Transactional
    public AgentRunResponse runAgent(String cveExternalId, AgentRunRequest request) {
        List<AssetCriterionDto> criteria = request.criteria() != null ? request.criteria() : List.of();

        InventoryResolutionResponse invResp = inventoryResolutionService.resolveInventory(criteria);
        FalsePositiveAnalysisResponse fpResp = falsePositiveAnalysisService.analyzeFalsePositives(cveExternalId, criteria);
        EolAnalysisResponse eolResp = eolAnalysisService.analyzeEol(criteria);

        AgentTaskMetaDto invMeta = inventoryMeta(cveExternalId, invResp, criteria);
        AgentTaskMetaDto fpMeta = fpMeta(cveExternalId, fpResp);
        AgentTaskMetaDto eolMeta = eolMeta(cveExternalId, eolResp);

        Map<String, AgentTaskMetaDto> taskMeta = new LinkedHashMap<>();
        taskMeta.put("review-asset-inventory", invMeta);
        taskMeta.put("find-false-positive", fpMeta);
        taskMeta.put("end-of-life-analysis", eolMeta);

        List<String> completedTaskIds = new ArrayList<>();
        if (!invResp.resolved().isEmpty()) completedTaskIds.add("review-asset-inventory");
        completedTaskIds.add("find-false-positive");
        if (!eolResp.results().isEmpty()) completedTaskIds.add("end-of-life-analysis");

        Map<String, String> confidenceMap = new LinkedHashMap<>();
        taskMeta.forEach((k, v) -> confidenceMap.put(k, v.confidence()));
        runbookService.saveAgentRun(cveExternalId, confidenceMap, taskMeta, completedTaskIds);

        return new AgentRunResponse(
                invResp.resolved(),
                invResp.totalAssets(),
                fpResp.results(),
                eolResp.results(),
                taskMeta,
                completedTaskIds,
                Instant.now().toString()
        );
    }

    // -------------------------------------------------------------------------
    // Per-task metadata derivation
    // -------------------------------------------------------------------------

    private AgentTaskMetaDto inventoryMeta(
            String cveId,
            InventoryResolutionResponse resp,
            List<AssetCriterionDto> criteria
    ) {
        if (openAiClient.isAvailable() && !criteria.isEmpty()) {
            String user = "CVE: " + cveId + ". "
                    + "Inventory resolution: " + resp.resolved().size() + " software version(s) matched, "
                    + resp.totalAssets() + " total asset(s). "
                    + "Criteria searched: " + summariseCriteria(criteria) + ".";
            AgentTaskMetaDto meta = callOpenAi(user);
            if (meta != null) return meta;
        }
        return algorithmicInventoryMeta(resp);
    }

    private AgentTaskMetaDto fpMeta(String cveId, FalsePositiveAnalysisResponse resp) {
        if (openAiClient.isAvailable() && !resp.results().isEmpty()) {
            long fpCount = resp.results().stream().filter(r -> r.falsePositive()).count();
            boolean hasVex = resp.results().stream()
                    .anyMatch(r -> r.vendorAdvisory() != null && !r.vendorAdvisory().isBlank());
            String user = "CVE: " + cveId + ". "
                    + "False-positive analysis: " + resp.results().size() + " software row(s) checked, "
                    + fpCount + " confirmed false positive(s). "
                    + "Vendor VEX/advisory data present: " + hasVex + ". "
                    + "Status tones: " + resp.results().stream()
                            .map(r -> r.statusTone()).distinct().toList() + ".";
            AgentTaskMetaDto meta = callOpenAi(user);
            if (meta != null) return meta;
        }
        return algorithmicFpMeta(resp);
    }

    private AgentTaskMetaDto eolMeta(String cveId, EolAnalysisResponse resp) {
        if (openAiClient.isAvailable() && !resp.results().isEmpty()) {
            long eolCount = resp.results().stream()
                    .filter(r -> r.lifecycle() != null && !r.lifecycle().equals("Supported")
                            && !r.lifecycle().equals("Unknown"))
                    .count();
            String user = "CVE: " + cveId + ". "
                    + "EOL analysis: " + resp.results().size() + " software version(s) checked, "
                    + eolCount + " at or near end-of-life. "
                    + "Lifecycle statuses: " + resp.results().stream()
                            .map(r -> r.lifecycle()).distinct().toList() + ".";
            AgentTaskMetaDto meta = callOpenAi(user);
            if (meta != null) return meta;
        }
        return algorithmicEolMeta(resp);
    }

    // -------------------------------------------------------------------------
    // OpenAI call
    // -------------------------------------------------------------------------

    private AgentTaskMetaDto callOpenAi(String userPrompt) {
        try {
            String raw = openAiClient.chat(SYSTEM_PROMPT, userPrompt, new AiCallOptions(null, 0.1, 120, true));
            if (raw == null || raw.isBlank()) return null;
            JsonNode node = objectMapper.readTree(raw);
            String confidence = node.path("confidence").asText(null);
            String reasoning = node.path("reasoning").asText(null);
            if (confidence == null || reasoning == null) return null;
            if (!confidence.equals("HIGH") && !confidence.equals("MEDIUM") && !confidence.equals("LOW")) {
                confidence = "MEDIUM";
            }
            return new AgentTaskMetaDto("AGENT", confidence, reasoning);
        } catch (Exception e) {
            log.warn("OpenAI agent call failed, using algorithmic fallback: {}", e.getMessage());
            return null;
        }
    }

    // -------------------------------------------------------------------------
    // Algorithmic fallbacks
    // -------------------------------------------------------------------------

    static AgentTaskMetaDto algorithmicInventoryMeta(InventoryResolutionResponse resp) {
        if (resp.totalAssets() > 0 && !resp.resolved().isEmpty()) {
            return new AgentTaskMetaDto("AGENT", "HIGH",
                    resp.totalAssets() + " asset(s) matched via inventory resolution against "
                    + resp.resolved().size() + " software identity record(s).");
        }
        if (resp.totalAssets() > 0) {
            return new AgentTaskMetaDto("AGENT", "MEDIUM",
                    resp.totalAssets() + " asset(s) matched. No additional inventory resolution records found.");
        }
        return new AgentTaskMetaDto("AGENT", "LOW",
                "No assets matched for the CVE criteria. Inventory may be incomplete or CVE CPE data is too broad.");
    }

    static AgentTaskMetaDto algorithmicFpMeta(FalsePositiveAnalysisResponse resp) {
        long fpCount = resp.results().stream().filter(r -> r.falsePositive()).count();
        boolean hasVex = resp.results().stream()
                .anyMatch(r -> r.vendorAdvisory() != null && !r.vendorAdvisory().isBlank());
        if (hasVex && !resp.results().isEmpty()) {
            int n = resp.results().size();
            return new AgentTaskMetaDto("AGENT", "HIGH",
                    n + " software entr" + (n == 1 ? "y" : "ies") + " checked against vendor VEX and advisory data. "
                    + fpCount + " false positive(s) identified.");
        }
        if (!resp.results().isEmpty()) {
            int n = resp.results().size();
            return new AgentTaskMetaDto("AGENT", "MEDIUM",
                    n + " software entr" + (n == 1 ? "y" : "ies") + " checked. "
                    + "No vendor VEX or advisory data — determination based on CVE correlation only.");
        }
        return new AgentTaskMetaDto("AGENT", "LOW",
                "No matched software rows available for false-positive analysis.");
    }

    static AgentTaskMetaDto algorithmicEolMeta(EolAnalysisResponse resp) {
        long withData = resp.results().stream()
                .filter(r -> r.lifecycle() != null && !r.lifecycle().equals("Supported"))
                .count();
        if (!resp.results().isEmpty() && withData > 0) {
            return new AgentTaskMetaDto("AGENT", "HIGH",
                    resp.results().size() + " software version(s) checked against EOL catalog. "
                    + withData + " flagged as end-of-life or near end-of-life.");
        }
        if (!resp.results().isEmpty()) {
            return new AgentTaskMetaDto("AGENT", "MEDIUM",
                    resp.results().size() + " software version(s) checked. All currently supported or no EOL data found.");
        }
        return new AgentTaskMetaDto("AGENT", "LOW",
                "No software versions available for EOL analysis. Complete asset inventory first.");
    }

    private static String summariseCriteria(List<AssetCriterionDto> criteria) {
        return criteria.stream()
                .map(c -> c.software() + (c.version() != null && !c.version().isBlank() ? "@" + c.version() : ""))
                .toList()
                .toString();
    }
}
