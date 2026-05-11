package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.client.http.AdvisoryFetchService;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import com.prototype.vulnwatch.dto.FixRecordResponse;
import com.prototype.vulnwatch.dto.SavedCveInvestigationSummaryResponse;
import com.prototype.vulnwatch.service.FixRecordService;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.service.ApplicabilityAssessmentService;
import com.prototype.vulnwatch.service.CveAiSolutionPersistenceService;
import com.prototype.vulnwatch.service.CveDetailQueryFacade;
import com.prototype.vulnwatch.service.CveInvestigationAiSummaryService;
import com.prototype.vulnwatch.service.CveInvestigationSummaryService;
import com.prototype.vulnwatch.service.CveInvestigationSummaryPersistenceService;
import com.prototype.vulnwatch.service.CveWorkflowFacade;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.InvestigationService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Controller for CVE drill-down functionality
 */
@RestController
@RequestMapping("/api/cve-detail")
@RequiredArgsConstructor
public class CveDetailController {

    private final CveDetailQueryFacade queryFacade;
    private final CveWorkflowFacade workflowFacade;
    private final CveInvestigationSummaryService summaryService;
    private final CveInvestigationAiSummaryService aiSummaryService;
    private final CveInvestigationSummaryPersistenceService summaryPersistenceService;
    private final CveAiSolutionPersistenceService aiSolutionPersistenceService;
    private final AdvisoryFetchService advisoryFetchService;
    private final OpenAiClient openAiClient;
    private final com.fasterxml.jackson.databind.ObjectMapper objectMapper;
    private final WorkspaceService workspaceService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;
    private final FixRecordService fixRecordService;

    /**
     * GET /api/cve-detail/{cveId}
     * Get CVE detail with summary, key signals, and available actions
     */
    @GetMapping("/{cveId}")
    public ResponseEntity<CveDetailResponse> getCveDetail(
            @PathVariable String cveId) {
        return queryFacade.getCveDetail(cveId);
    }

    @GetMapping("/{cveId}/vex-evidence")
    public ResponseEntity<VexEvidenceResponse> getVexEvidence(
            @PathVariable String cveId,
            @RequestParam("componentId") UUID componentId) {
        return queryFacade.getVexEvidence(cveId, componentId);
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation
     * Create a new investigation for this CVE
     */
    @PostMapping("/{cveId}/investigation")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<InvestigationDto> createInvestigation(
            @PathVariable String cveId,
            @RequestBody CreateInvestigationRequest request) {
        return workflowFacade.createInvestigation(cveId, request);
    }

    /**
     * PUT /api/cve-detail/investigation/{investigationId}
     * Update an existing investigation
     */
    @PutMapping("/investigation/{investigationId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<InvestigationDto> updateInvestigation(
            @PathVariable Long investigationId,
            @RequestBody InvestigationService.InvestigationUpdateRequest request) {
        return workflowFacade.updateInvestigation(investigationId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/investigation/submit
     * Create-or-update investigation in a single call (upsert semantics)
     */
    @PostMapping("/{cveId}/investigation/submit")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<InvestigationDto> submitInvestigation(
            @PathVariable String cveId,
            @RequestBody InvestigationService.SubmitInvestigationRequest request) {
        return workflowFacade.submitInvestigation(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/assessment/submit
     * Create-or-update-and-complete assessment in a single call (upsert + complete)
     */
    @PostMapping("/{cveId}/assessment/submit")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AssessmentDto> submitAssessment(
            @PathVariable String cveId,
            @RequestBody ApplicabilityAssessmentService.SubmitAssessmentRequest request) {
        return workflowFacade.submitAssessment(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/applicability-assessment
     * Start applicability assessment wizard
     */
    @PostMapping("/{cveId}/applicability-assessment")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AssessmentDto> createAssessment(
            @PathVariable String cveId) {
        return workflowFacade.createAssessment(cveId);
    }

    /**
     * PUT /api/cve-detail/applicability-assessment/{assessmentId}
     * Update assessment (step by step)
     */
    @PutMapping("/applicability-assessment/{assessmentId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AssessmentDto> updateAssessment(
            @PathVariable Long assessmentId,
            @RequestBody ApplicabilityAssessmentService.AssessmentUpdateRequest request) {
        return workflowFacade.updateAssessment(assessmentId, request);
    }

    /**
     * POST /api/cve-detail/applicability-assessment/{assessmentId}/complete
     * Complete the assessment with final result
     */
    @PostMapping("/applicability-assessment/{assessmentId}/complete")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AssessmentDto> completeAssessment(
            @PathVariable Long assessmentId,
            @RequestBody CompleteAssessmentRequest request) {
        return workflowFacade.completeAssessment(assessmentId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/manual-finding
     * Create manual finding (add to backlog)
     */
    @PostMapping("/{cveId}/manual-finding")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<ManualFindingResponse> createManualFinding(
            @PathVariable String cveId,
            @RequestBody CreateManualFindingRequest request) {
        return workflowFacade.createManualFinding(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/suppress
     * Suppress this CVE for the organization
     */
    @PostMapping("/{cveId}/suppress")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<SuppressionResponse> suppressCve(
            @PathVariable String cveId,
            @RequestBody SuppressRequest request) {
        return workflowFacade.suppressCve(cveId, request);
    }

    /**
     * POST /api/cve-detail/{cveId}/export
     * Export CVE report in various formats
     */
    @PostMapping("/{cveId}/export")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public ResponseEntity<ExportResponse> exportCveReport(
            @PathVariable String cveId,
            @RequestBody ExportRequest request) {
        return queryFacade.exportCveReport(cveId, request);
    }

    @PostMapping("/{cveId}/investigation-summary")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<CveInvestigationSummaryResponse> generateInvestigationSummary(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> request) {
        CveInvestigationSummaryResponse summary = summaryService.generateSummary(cveId, request);
        summaryPersistenceService.saveSummary(cveId, request, summary, "deterministic");
        return ResponseEntity.ok(summary);
    }

    @PostMapping("/{cveId}/investigation-ai-summary")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<CveInvestigationSummaryResponse> generateInvestigationAiSummary(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> request) {
        assertDemoAllowsAiAction();
        CveInvestigationSummaryResponse summary = aiSummaryService.generateAiSummary(cveId, request);
        summaryPersistenceService.saveSummary(cveId, request, summary, "ai");
        return ResponseEntity.ok(summary);
    }

    @GetMapping("/{cveId}/saved-investigation-summary")
    public ResponseEntity<SavedCveInvestigationSummaryResponse> getSavedInvestigationSummary(
            @PathVariable String cveId) {
        return ResponseEntity.ok(summaryPersistenceService.getSavedSummary(cveId));
    }

    /**
     * GET /api/cve-detail/{cveId}/fixes
     * Return previously generated fix records for this CVE.
     */
    @GetMapping("/{cveId}/fixes")
    public ResponseEntity<List<FixRecordResponse>> getFixRecords(@PathVariable String cveId) {
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        return ResponseEntity.ok(fixRecordService.getFixRecords(tenant, cveId));
    }

    /**
     * GET /api/cve-detail/software-fixes?software={name}
     * Return all fix records for the tenant where softwareEntities contains the given software name.
     */
    @GetMapping("/software-fixes")
    public ResponseEntity<List<FixRecordResponse>> getFixRecordsBySoftware(
            @org.springframework.web.bind.annotation.RequestParam(required = false) String software) {
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        return ResponseEntity.ok(fixRecordService.getFixRecordsBySoftware(tenant, software));
    }

    /**
     * POST /api/cve-detail/{cveId}/generate-fixes
     * Generate (or regenerate) fix records for this CVE using references + OpenAI.
     */
    public record GenerateFixesRequest(
            java.util.List<GenerateFixesSoftwareEntry> additionalSoftware
    ) {}
    public record GenerateFixesSoftwareEntry(
            String name, String vendor, String version, int assetCount
    ) {}

    @PostMapping("/{cveId}/generate-fixes")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<List<FixRecordResponse>> generateFixRecords(
            @PathVariable String cveId,
            @org.springframework.web.bind.annotation.RequestBody(required = false) GenerateFixesRequest body
    ) {
        assertDemoAllowsAiAction();
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        java.util.List<GenerateFixesSoftwareEntry> extra = body != null && body.additionalSoftware() != null
                ? body.additionalSoftware() : java.util.List.of();
        return ResponseEntity.ok(fixRecordService.generateFixRecords(tenant, cveId, extra));
    }

    /**
     * POST /api/cve-detail/{cveId}/analyst-fixes
     * Save analyst-entered solution text as fix records (one per software row).
     * Replaces any previous ANALYST-sourced fix records for this CVE.
     */
    public record AnalystFixesRequest(
            java.util.List<FixRecordService.AnalystFixEntry> solutions
    ) {}

    @PostMapping("/{cveId}/analyst-fixes")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<List<FixRecordResponse>> saveAnalystFixes(
            @PathVariable String cveId,
            @RequestBody AnalystFixesRequest body) {
        com.prototype.vulnwatch.domain.Tenant tenant = workspaceService.getWorkspace();
        java.util.List<FixRecordService.AnalystFixEntry> solutions =
                body.solutions() != null ? body.solutions() : java.util.List.of();
        return ResponseEntity.ok(fixRecordService.saveAnalystFixes(tenant, cveId, solutions));
    }

    /**
     * GET /api/cve-detail/{cveId}/ai-solution
     * Return the previously saved AI remediation recommendation for this CVE.
     */
    @GetMapping("/{cveId}/ai-solution")
    public ResponseEntity<AiSolutionResponse> getSavedAiSolution(@PathVariable String cveId) {
        java.util.Optional<CveAiSolutionPersistenceService.SavedAiSolution> saved =
                aiSolutionPersistenceService.getSavedAiSolution(cveId);
        if (saved.isEmpty()) return ResponseEntity.notFound().build();
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(saved.get().contentJson(), Map.class);
            AiSolutionResponse r = new AiSolutionResponse();
            r.setSuccess(true);
            r.setData(parsed);
            r.setGeneratedAt(saved.get().generatedAt());
            return ResponseEntity.ok(r);
        } catch (Exception e) {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * POST /api/cve-detail/{cveId}/ai-solution
     * Generate and persist a comprehensive structured remediation recommendation using OpenAI.
     */
    @PostMapping("/{cveId}/ai-solution")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AiSolutionResponse> generateAiSolution(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> recommendationContext) {
        assertDemoAllowsAiAction();

        String softwarePrompt = stringValue(recommendationContext.get("softwareRecommendationPrompt"));
        if (softwarePrompt != null && !softwarePrompt.isBlank()) {
            AiSolutionResponse r = new AiSolutionResponse();
            if (!openAiClient.isAvailable()) {
                r.setSuccess(false);
                r.setRecommendation(trimWords(buildSoftwareFallbackRecommendation(recommendationContext), 200));
                return ResponseEntity.ok(r);
            }

            String systemPrompt = """
                    You are a cybersecurity remediation advisor writing for an enterprise IT operations team.
                    Follow the user's instructions exactly. Return direct operational guidance only.
                    Keep the final answer to 200 words or fewer.
                    """;
            String raw = openAiClient.chatCompletion(systemPrompt, softwarePrompt, 800);
            if (raw == null || raw.isBlank()) {
                r.setSuccess(false);
                r.setRecommendation(trimWords(buildSoftwareFallbackRecommendation(recommendationContext), 200));
                return ResponseEntity.ok(r);
            }
            r.setSuccess(true);
            r.setRecommendation(trimWords(raw.trim(), 200));
            return ResponseEntity.ok(r);
        }

        if (!openAiClient.isAvailable()) {
            AiSolutionResponse r = new AiSolutionResponse();
            r.setSuccess(false);
            r.setRecommendation("OpenAI is not configured. Please set app.openai.api-key in application properties.");
            return ResponseEntity.ok(r);
        }

        // Fetch vendor advisory content from URLs supplied by the frontend
        StringBuilder advisoryBuilder = new StringBuilder();
        Object urlsObj = recommendationContext.get("advisory_urls");
        if (urlsObj instanceof java.util.List<?> rawList) {
            List<String> advisoryUrls = rawList.stream()
                .filter(o -> o instanceof String)
                .map(o -> (String) o)
                .toList();
            if (!advisoryUrls.isEmpty()) {
                String fetched = advisoryFetchService.fetchAdvisoryContent(advisoryUrls);
                if (!fetched.isBlank()) advisoryBuilder.append(fetched);
            }
        }
        // Also query MSRC JSON API for structured KB/patch data (works even when MSRC HTML pages are JS-rendered)
        String msrcData = advisoryFetchService.fetchMsrcPatchInfo(cveId);
        if (!msrcData.isBlank()) advisoryBuilder.append(msrcData);
        String advisoryContent = advisoryBuilder.toString().trim();

        String systemPrompt = """
                You are a senior security engineer writing a highly specific, actionable remediation
                advisory for a vulnerability management dashboard. Every sentence must name the actual
                product, patch ID, KB number, version, asset count, or EOL date drawn directly from
                the supplied CVE context. NEVER write generic sentences like "apply mitigations per
                vendor instructions" or "monitor for vendor updates" — those are useless to the team.
                Instead write instructions like:
                  "Deploy KB5034441 to all 47 Windows 10 22H2 endpoints via WSUS before end of day."
                  "Block inbound SMTP relay on port 25 at the perimeter firewall until patch is applied."
                  "Run 'winver' on a patched host and confirm build 19045.3930 or later."

                Respond with valid JSON matching EXACTLY this schema (no extra keys, no markdown fences):
                {
                  "title": "<CVE-ID> Remediation Summary — Your Organization",
                  "affected_scope": "<N assets · N software identities · N components>",
                  "bottom_line": {
                    "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
                    "cvss": "<score>",
                    "kev_status": "<Listed in CISA KEV | Not in KEV>",
                    "patch_status": "<Patch Available | No Patch Available>",
                    "summary": "<1-2 sentences naming the product, attack type, and blast radius in your org>"
                  },
                  "what_is_happening": {
                    "description": "<2-3 sentences: name the vulnerable component, the exact mechanism (e.g. heap overflow in Outlook's URL parser), and why your N assets are at risk>",
                    "attack_steps": [
                      "<step naming the specific protocol or component — e.g. 'Attacker sends crafted MIME email to Outlook client'>",
                      "<step describing what the vulnerable code does — e.g. 'Outlook processes the MonikerLink URL via preview pane without user click'>",
                      "<step describing impact — e.g. 'NTLM credential hash leaks to attacker-controlled SMB server'>"
                    ],
                    "interaction_note": "<zero-click / single-click / requires user to open attachment — be specific>"
                  },
                  "primary_fix": {
                    "action": "<Install / Apply / Upgrade>",
                    "patch_id": "<KB number, advisory ID, or package version — from vendor_intelligence in context>",
                    "target_version": "<exact build or version from context, e.g. 16.0.17231.20236>",
                    "applies_to": "<exact product editions and install types from context>",
                    "reboot_required": <true|false>,
                    "verification": "<exact CLI command or UI step to confirm — e.g. 'Get-HotFix -Id KB5034441' or 'Help > About shows version 16.0.x'>"
                  },
                  "timeline": [
                    {
                      "window": "Next 24 hours", "color": "red", "label": "Immediate actions",
                      "actions": [
                        "<specific action naming the product and what to disable/block — e.g. 'Disable Outlook preview pane for all N Exchange Online mailboxes via OWA policy'>",
                        "<specific network control — e.g. 'Block outbound SMB (port 445) to untrusted IPs at the perimeter firewall'>"
                      ]
                    },
                    {
                      "window": "Days 1–7", "color": "amber", "label": "Deploy the patch",
                      "actions": [
                        "<specific patch deployment step naming the KB/package and target system count — e.g. 'Push KB5034441 via WSUS to all N Windows endpoints; prioritise internet-facing systems first'>",
                        "<specific validation step — e.g. 'Confirm build 19045.3930 via endpoint management console; flag non-compliant hosts'>"
                      ]
                    },
                    {
                      "window": "Days 8–30", "color": "green", "label": "Validate & harden",
                      "actions": [
                        "<specific hardening or compliance action — e.g. 'Enable Attack Surface Reduction rule GUID 92E97FA1... to block Office from spawning child processes'>",
                        "<EOL or upgrade action if relevant — e.g. 'Begin migration of N EOL Windows 10 20H2 hosts to Windows 11 23H2 per upgrade path'>",
                        "<evidence closure step — e.g. 'Update org_cve_records applicability state to FIXED and close investigation ticket'>"
                      ]
                    }
                  ],
                  "compensating_controls": [
                    {"control": "<specific control naming the product feature or tool>", "effort": "<Low|Medium|High>", "effectiveness": "<Low|Medium|High>"}
                  ],
                  "rollback_plan": [
                    "<specific rollback step — e.g. 'Use WSUS to uninstall KB5034441 on affected hosts if regression observed'>",
                    "<verification step — e.g. 'Re-run baseline scans and confirm no new critical failures before re-patching'>"
                  ],
                  "lifecycle_warning": {
                    "product": "<exact product name from context or null>",
                    "eol_date": "<ISO date from context or null>",
                    "is_eol": <true|false>,
                    "lifecycle_status": "<Active Support|Extended Support|End of Life|null>",
                    "upgrade_recommendation": "<specific upgrade path — e.g. 'Upgrade from Windows 10 21H2 to Windows 11 23H2; free in-place upgrade available via Windows Update' or null>"
                  },
                  "reasoning_trace": [
                    "Source triage: <what sources were used and their trust tier>",
                    "Asset correlation: <how many assets matched and by what CPE/version>",
                    "Patch extraction: <which KB/build was identified and from which source>",
                    "Urgency scoring: <why this SLA — KEV, EPSS, PoC, asset count>"
                  ],
                  "evidence_gaps": "<specific gaps — e.g. 'No EPSS score available; fixed version not confirmed in vendor_intelligence for macOS builds'>",
                  "confidence_score": <integer 0-100>,
                  "confidence_rationale": "<short phrase explaining the score — e.g. 'KEV-listed with PoC and patch confirmed in MSRC advisory'>"
                }
                Hard rules:
                - SCOPE: The affected_entities list contains ONLY the products with confirmed impact. All recommendations must be scoped exclusively to those products. Do NOT mention products not in the list.
                - If vendor advisory content is provided, extract patch KB numbers, fixed versions, workarounds, and compensating controls from it and use them as the PRIMARY source. Cite the advisory source in your reasoning_trace.
                - If advisory content is absent or incomplete, use your training knowledge for the specific CVE (e.g. well-known KB numbers from MSRC advisories) and prefix with "Per MSRC:" or "Per NVD:".
                - Never output the literal string "null" or "N/A" for patch_id or target_version — if genuinely unknown, omit the field entirely.
                - Every action in timeline.actions must name the specific product, patch ID, or asset count from context.
                - Never use the words "vendor instructions", "monitor for updates", or "additional security measures".
                - compensating_controls: at least 2 entries, each naming a specific product feature or network control relevant to the impacted products.
                - rollback_plan: at least 2 steps, each referencing the specific patch or change being rolled back.
                """;

        String userPrompt = "CVE context (affected_entities contains ONLY products with confirmed impact — asset_count > 0; ignore all other products):\n"
                + toJson(recommendationContext)
                + (advisoryContent.isBlank() ? "" :
                   "\n\nVENDOR ADVISORY CONTENT (fetched from official advisory pages — use patches, KB numbers, workarounds, and compensating controls found here as the PRIMARY source for your recommendation):\n"
                   + advisoryContent);

        String raw = openAiClient.chatCompletionJson(systemPrompt, userPrompt, 3500);

        if (raw == null || raw.isBlank()) {
            AiSolutionResponse r = new AiSolutionResponse();
            r.setSuccess(false);
            r.setRecommendation("AI recommendation generation failed. Please check the OpenAI configuration and try again.");
            return ResponseEntity.ok(r);
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(raw, Map.class);
            // Persist to database
            try {
                aiSolutionPersistenceService.saveAiSolution(cveId, raw);
            } catch (Exception saveError) {
                // Non-fatal: log and continue
                org.slf4j.LoggerFactory.getLogger(CveDetailController.class)
                        .warn("Failed to persist AI solution for {}: {}", cveId, saveError.getMessage());
            }
            AiSolutionResponse r = new AiSolutionResponse();
            r.setSuccess(true);
            r.setData(parsed);
            return ResponseEntity.ok(r);
        } catch (Exception parseError) {
            AiSolutionResponse r = new AiSolutionResponse();
            r.setSuccess(true);
            r.setRecommendation(raw.trim());
            return ResponseEntity.ok(r);
        }
    }

    private String buildSoftwareFallbackRecommendation(Map<String, Object> recommendationContext) {
        Object softwareObj = recommendationContext.get("software");
        Object vulnObj = recommendationContext.get("vulnerability");
        String softwareName = softwareObj instanceof Map<?, ?> softwareMap ? stringValue(softwareMap.get("name")) : null;
        String softwareVersion = softwareObj instanceof Map<?, ?> softwareMap ? stringValue(softwareMap.get("version")) : null;
        String cveId = vulnObj instanceof Map<?, ?> vulnMap ? stringValue(vulnMap.get("id")) : null;
        String cveSummary = vulnObj instanceof Map<?, ?> vulnMap ? stringValue(vulnMap.get("summary")) : null;
        String affectedAssets = stringValue(recommendationContext.get("affected_assets"));
        String severity = stringValue(recommendationContext.get("severity"));
        return String.join(" ",
                "Review",
                nonBlankJoin(" ", softwareName, softwareVersion),
                "for",
                nonBlankJoin(" ", cveId, cveSummary),
                severity == null ? "" : "Severity " + severity + ".",
                affectedAssets == null ? "" : affectedAssets + " assets are affected.",
                "Apply the vendor fix first, use network or access restrictions if patching is delayed, verify the corrected version, and test rollback on a non-production host before broad rollout.");
    }

    private String nonBlankJoin(String separator, String... values) {
        return java.util.Arrays.stream(values)
                .filter(value -> value != null && !value.isBlank())
                .reduce((left, right) -> left + separator + right)
                .orElse("");
    }

    private String stringValue(Object value) {
        return value == null ? null : String.valueOf(value).trim();
    }

    private String trimWords(String value, int limit) {
        if (value == null || value.isBlank() || limit <= 0) {
            return value == null ? "" : value.trim();
        }
        String[] words = value.trim().split("\\s+");
        if (words.length <= limit) {
            return value.trim();
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < limit; i++) {
            if (i > 0) builder.append(' ');
            builder.append(words[i]);
        }
        return builder.toString().trim();
    }

    /**
     * GET /api/cve-detail/{cveId}/ai-actions
     * Return previously persisted AI-generated required actions for this CVE.
     */
    @GetMapping("/{cveId}/ai-actions")
    public ResponseEntity<AiActionsResponse> getSavedAiActions(@PathVariable String cveId) {
        return aiSolutionPersistenceService.getSavedAiActions(cveId)
                .map(saved -> {
                    try {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> parsed = objectMapper.readValue(saved.contentJson(), Map.class);
                        AiActionsResponse r = new AiActionsResponse();
                        r.setSuccess(true);
                        r.setData(parsed);
                        r.setGeneratedAt(saved.generatedAt());
                        return ResponseEntity.ok(r);
                    } catch (Exception e) {
                        return ResponseEntity.ok(new AiActionsResponse());
                    }
                })
                .orElseGet(() -> {
                    AiActionsResponse r = new AiActionsResponse();
                    r.setSuccess(false);
                    return ResponseEntity.ok(r);
                });
    }

    /**
     * POST /api/cve-detail/{cveId}/ai-actions
     * Generate top 3 prioritised analyst actions using OpenAI based on full CVE context.
     */
    @PostMapping("/{cveId}/ai-actions")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ResponseEntity<AiActionsResponse> generateAiActions(
            @PathVariable String cveId,
            @RequestBody Map<String, Object> context) {
        assertDemoAllowsAiAction();

        if (!openAiClient.isAvailable()) {
            AiActionsResponse r = new AiActionsResponse();
            r.setSuccess(false);
            r.setError("OpenAI is not configured.");
            return ResponseEntity.ok(r);
        }

        String systemPrompt = """
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

        String userPrompt = "CVE operational context:\n" + toJson(context);
        String raw = openAiClient.chatCompletionJson(systemPrompt, userPrompt, 1200);

        if (raw == null || raw.isBlank()) {
            AiActionsResponse r = new AiActionsResponse();
            r.setSuccess(false);
            r.setError("AI action generation failed.");
            return ResponseEntity.ok(r);
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(raw, Map.class);
            try {
                aiSolutionPersistenceService.saveAiActions(cveId, raw);
            } catch (Exception saveError) {
                org.slf4j.LoggerFactory.getLogger(CveDetailController.class)
                        .warn("Failed to persist AI actions for {}: {}", cveId, saveError.getMessage());
            }
            AiActionsResponse r = new AiActionsResponse();
            r.setSuccess(true);
            r.setData(parsed);
            r.setGeneratedAt(Instant.now());
            return ResponseEntity.ok(r);
        } catch (Exception e) {
            AiActionsResponse r = new AiActionsResponse();
            r.setSuccess(false);
            r.setError("Failed to parse AI response: " + e.getMessage());
            return ResponseEntity.ok(r);
        }
    }

    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            return obj.toString();
        }
    }

    // DTOs

    @Data
    public static class AiActionsResponse {
        private boolean success;
        private Map<String, Object> data;
        private String error;
        private Instant generatedAt;
    }

    private void assertDemoAllowsAiAction() {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsAiAction(workspaceService.getWorkspace());
        }
    }

    @Data
    public static class CveDetailResponse {
        private CveSummary summary;
        private KeySignals signals;
        private List<InvestigationDto> investigations;
        private List<AssessmentDto> assessments;
        private List<MatchedSoftwareDto> matchedSoftware;
        private List<VendorIntelligenceDto> vendorIntelligence;
        private List<CveReference> references;
        private List<FixRecordResponse> fixes;
        private java.util.UUID suppressedByRuleId;
        private String suppressedByRuleName;
    }

    @Data
    public static class CveReference {
        private String url;
        private String source;
        private List<String> tags;
    }

    @Data
    public static class VendorIntelligenceDto {
        private String source;
        private String ecosystem;
        private String packageName;
        private String affectedVersions;
        private String fixedVersion;
        private String cpe;
        private String vexStatus;
    }

    @Data
    public static class CveSummary {
        private String externalId;
        private String title;
        private String description;
        private String severity;
        private Double cvssScore;
        private String cvssVector;
        private Double epssScore;
        private Double epssSevenDayDelta;
        /** BLG-016: when the EPSS score was last refreshed from the FIRST.org feed. */
        private Instant epssUpdatedAt;
        private String cweIds;
        private Instant publishedAt;
        private Instant modifiedAt;
        private VulnerabilitySource source;
        private Boolean inKev;
        private LocalDate kevDateAdded;
        private LocalDate kevDueDate;
        private String kevRequiredAction;
    }

    @Data
    public static class KeySignals {
        private boolean exploitAvailable;
        private String exploitReason;
        private boolean systemsImpacted;
        private long componentCount;
        private long softwareCount;
        private long assetCount;
        private boolean patchAvailable;
        private String patchVersions;
    }

    @Data
    public static class InvestigationDto {
        private Long id;
        private String cveId;
        private Investigation.InvestigationStatus status;
        private String assignedTo;
        private Investigation.InvestigationPriority priority;
        private String notes;
        private Instant createdAt;
        private Instant updatedAt;
    }

    @Data
    public static class AssessmentDto {
        private Long id;
        private String cveId;
        private ApplicabilityAssessment.AssessmentStatus status;
        private Boolean softwareDetected;
        private Boolean vulnerableVersionPresent;
        private Boolean vulnerableConfiguration;
        private ApplicabilityAssessment.AssessmentResult finalResult;
        private ApplicabilityAssessment.ConfidenceLevel confidenceLevel;
        private String justification;
        private String recommendedAction;
        private Instant createdAt;
        private Instant completedAt;
    }

    @Data
    public static class MatchedSoftwareDto {
        private UUID componentId;
        private UUID assetId;
        private String assetName;
        private String assetIdentifier;
        private String assetType;
        private String ecosystem;
        private String packageName;
        private String version;
        private ApplicabilityState applicabilityState;
        private String applicabilityReason;
        private String applicabilityReasonDetail;
        private ImpactState computedImpactState;
        private String computedImpactReason;
        private String computedImpactReasonDetail;
        private ImpactState impactState;
        private String impactReason;
        private String impactReasonDetail;
        private String vexStatus;
        private String vexProvider;
        private String vexFreshness;
        private String vexSource;
        private UUID matchedVexAssertionId;
        private String analystDisposition;
        private String analystReason;
        private String matchedBy;
        private boolean eligibleForFinding;
        private String findingEligibilityReason;
        private String findingEligibilityDetail;
        private String eolSlug;
        private String eolCycle;
        private java.time.LocalDate eolDate;
        private Boolean isEol;
        private Integer eolDaysRemaining;
        private java.time.LocalDate eolSupportEndDate;
        private String supportPhase;
        private String supportGroup;
        private UUID softwareIdentityId;
    }

    @Data
    public static class VexEvidenceResponse {
        private UUID componentId;
        private String assetName;
        private String assetIdentifier;
        private String assetType;
        private String ecosystem;
        private String installedVersion;
        private String matchedBy;
        private String applicabilityState;
        private String applicabilityReason;
        private String applicabilityReasonDetail;
        private UUID matchedVexAssertionId;
        private String sourceSystem;
        private String provider;
        private String status;
        private String trustTier;
        private String freshness;
        private String documentId;
        private String packageName;
        private String normalizedProductKey;
        private String versionExact;
        private String versionStart;
        private Boolean startInclusive;
        private String versionEnd;
        private Boolean endInclusive;
        private String fixedVersion;
        private Instant publishedAt;
        private Instant lastSeenAt;
        private String evidenceUrl;
        private String computedImpactState;
        private String computedImpactReason;
        private String computedImpactReasonDetail;
        private String impactState;
        private String impactReason;
        private String impactReasonDetail;
        private Map<String, Object> evidence;
    }

    @Data
    public static class CreateInvestigationRequest {
        private Investigation.InvestigationPriority priority;
    }

    @Data
    public static class CreateManualFindingRequest {
        private String justification;
        private List<String> componentIds;
        private Map<String, String> componentApplicabilityDecisions;
        private Map<String, String> componentAnalystDispositions;
        private String severity;
        private String dueDate;
        /** ASSET_CVE (default) or CVE_FIX */
        private String findingCreationMode;
        /** ADD_TO_EXISTING (default) or CREATE_NEW — only relevant for CVE_FIX mode */
        private String existingFindingBehavior;
    }

    @Data
    public static class ManualFindingResponse {
        private String cveId;
        private int eligibleComponentCount;
        private int createdCount;
        private int reopenedCount;
        private int alreadyOpenCount;
        private String message;
    }

    @Data
    public static class CompleteAssessmentRequest {
        private ApplicabilityAssessment.AssessmentResult result;
        private ApplicabilityAssessment.ConfidenceLevel confidence;
        private String justification;
        private String recommendedAction;
    }

    @Data
    public static class SuppressRequest {
        private String reason;
        private String justification;
        private Integer duration; // days
    }

    @Data
    public static class SuppressionResponse {
        private String cveId;
        private boolean suppressed;
        private String reason;
        private String suppressedBy;
        private Instant suppressedAt;
        private Instant expiresAt;
    }

    @Data
    public static class ExportRequest {
        private String format; // pdf, csv, json, excel
    }

    @Data
    public static class ExportResponse {
        private String cveId;
        private String format;
        private String content;
        private Instant generatedAt;
    }

    @Data
    public static class AiSolutionResponse {
        private boolean success;
        /** Plain-text fallback when JSON parsing fails or OpenAI unavailable. */
        private String recommendation;
        /** Structured JSON content from OpenAI JSON mode. */
        private Map<String, Object> data;
        /** Timestamp when this recommendation was generated/saved. */
        private Instant generatedAt;
    }
}
