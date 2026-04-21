package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

@Service
public class ServiceNowIncidentService {

    private static final Logger log = LoggerFactory.getLogger(ServiceNowIncidentService.class);
    private static final String DEFAULT_ASSIGNMENT_GROUP = "App-Sec Manager";

    /** Maps ServiceNow incident state codes to human-readable labels. */
    public static final Map<String, String> SNOW_STATE_LABELS = Map.of(
            "1", "New",
            "2", "In Progress",
            "3", "On Hold",
            "6", "Resolved",
            "7", "Closed",
            "8", "Canceled"
    );

    private static final Map<String, Integer> PRIORITY_MAP = Map.of(
            "CRITICAL", 1,
            "HIGH",     2,
            "MEDIUM",   3,
            "LOW",      4
    );

    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final FindingRepository findingRepository;

    public ServiceNowIncidentService(
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            FindingRepository findingRepository
    ) {
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.findingRepository = findingRepository;
    }

    /**
     * Creates one or more ServiceNow incidents for the given CVE, grouped by:
     * <ol>
     *   <li>Assignment group — assets with a known group are consolidated into one incident per group.</li>
     *   <li>Package name — assets without a group are grouped by software package; each becomes a
     *       separate incident with the default assignment group {@value DEFAULT_ASSIGNMENT_GROUP}.</li>
     * </ol>
     * After creation, each affected finding is updated with the incident number.
     */
    @Transactional
    public List<ServiceNowIncidentResponse> createIncidents(Tenant tenant, String cveId, CreateServiceNowIncidentRequest req) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config =
                serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                        .orElseThrow(() -> new ResponseStatusException(
                                SERVICE_UNAVAILABLE,
                                "ServiceNow is not configured for this tenant. Configure the ServiceNow connector first."
                        ));

        List<CreateServiceNowIncidentRequest.AffectedAsset> assets =
                req.affectedAssets() != null ? req.affectedAssets() : List.of();

        // Partition: assets with a known assignment group vs. those without
        List<CreateServiceNowIncidentRequest.AffectedAsset> withGroup = assets.stream()
                .filter(a -> a.assignmentGroup() != null && !a.assignmentGroup().isBlank())
                .collect(Collectors.toList());

        List<CreateServiceNowIncidentRequest.AffectedAsset> withoutGroup = assets.stream()
                .filter(a -> a.assignmentGroup() == null || a.assignmentGroup().isBlank())
                .collect(Collectors.toList());

        List<ServiceNowIncidentResponse> responses = new ArrayList<>();

        // Case (a): one incident per assignment group
        Map<String, List<CreateServiceNowIncidentRequest.AffectedAsset>> byGroup = withGroup.stream()
                .collect(Collectors.groupingBy(
                        a -> a.assignmentGroup().trim(),
                        LinkedHashMap::new,
                        Collectors.toList()
                ));
        for (Map.Entry<String, List<CreateServiceNowIncidentRequest.AffectedAsset>> entry : byGroup.entrySet()) {
            ServiceNowIncidentResponse resp = createSingleIncident(config, cveId, req, entry.getKey(), entry.getValue());
            linkFindingsToIncident(cveId, entry.getValue(), resp.incidentNumber());
            responses.add(resp);
        }

        // Case (b): one incident per software package, default assignment group
        Map<String, List<CreateServiceNowIncidentRequest.AffectedAsset>> byPackage = withoutGroup.stream()
                .collect(Collectors.groupingBy(
                        a -> a.packageName() != null && !a.packageName().isBlank() ? a.packageName() : "unknown",
                        LinkedHashMap::new,
                        Collectors.toList()
                ));
        for (Map.Entry<String, List<CreateServiceNowIncidentRequest.AffectedAsset>> entry : byPackage.entrySet()) {
            ServiceNowIncidentResponse resp = createSingleIncident(config, cveId, req, DEFAULT_ASSIGNMENT_GROUP, entry.getValue());
            linkFindingsToIncident(cveId, entry.getValue(), resp.incidentNumber());
            responses.add(resp);
        }

        // Fallback: no assets at all — create a single incident
        if (responses.isEmpty()) {
            responses.add(createSingleIncident(config, cveId, req, DEFAULT_ASSIGNMENT_GROUP, List.of()));
        }

        return responses;
    }

    /**
     * Fetches the current state of a ServiceNow incident by incident number.
     * Returns the human-readable label (e.g. "Resolved") or null if not found.
     */
    public String getIncidentStatus(ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config, String incidentNumber) {
        String endpoint = config.baseUrl()
                + "/api/now/table/incident?sysparm_query=number%3D" + incidentNumber
                + "&sysparm_fields=number%2Cstate&sysparm_limit=1";

        HttpHeaders headers = buildHeaders(config);
        HttpEntity<Void> requestEntity = new HttpEntity<>(headers);

        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    endpoint,
                    HttpMethod.GET,
                    requestEntity,
                    String.class,
                    "ServiceNow incident status fetch",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("ServiceNow status fetch failed: " + context.error().getMessage(), context.error())
                    )
            );

            JsonNode root = ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow incident status fetch");
            JsonNode resultArray = root.path("result");
            if (resultArray.isArray() && !resultArray.isEmpty()) {
                String stateCode = resultArray.get(0).path("state").asText(null);
                if (stateCode != null) {
                    return SNOW_STATE_LABELS.getOrDefault(stateCode, "Unknown (" + stateCode + ")");
                }
            }
        } catch (Exception e) {
            log.warn("Failed to fetch ServiceNow status for incident {}: {}", incidentNumber, e.getMessage());
        }
        return null;
    }

    // ── Private helpers ──────────────────────────────────────────────────────

    private ServiceNowIncidentResponse createSingleIncident(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String cveId,
            CreateServiceNowIncidentRequest req,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        Map<String, Object> payload = buildPayload(cveId, req, effectiveAssignmentGroup, groupAssets);

        String body;
        try {
            body = objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException e) {
            throw new ResponseStatusException(BAD_GATEWAY, "Failed to serialize incident payload: " + e.getMessage());
        }

        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        String endpoint = config.baseUrl() + "/api/now/table/incident";
        HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);

        ResponseEntity<String> response = outboundHttpClient.exchange(
                endpoint,
                HttpMethod.POST,
                requestEntity,
                String.class,
                "ServiceNow incident creation",
                outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                context -> new OutboundFailureDecision<>(
                        context.isRetryableByDefault(),
                        context.retryAfterDelayMs(),
                        context.error() instanceof RuntimeException rte ? rte
                                : new RuntimeException("ServiceNow incident creation failed: " + context.error().getMessage(), context.error())
                )
        );

        JsonNode root = ServiceNowApiResponseParser.parseJson(objectMapper, response, "ServiceNow incident creation");
        JsonNode result = root.path("result");

        String incidentNumber = result.path("number").asText(null);
        String sysId = result.path("sys_id").asText(null);

        if (incidentNumber == null || incidentNumber.isBlank()) {
            throw new ResponseStatusException(BAD_GATEWAY, "ServiceNow returned an unexpected response — incident number missing");
        }

        // Associate additional CIs via the task_ci M2M table
        if (sysId != null && !sysId.isBlank()) {
            linkAdditionalCis(config, sysId, groupAssets);
            // Create a Task SLA record for the remediation due date
            if (req.taskSlaDueDate() != null && !req.taskSlaDueDate().isBlank()) {
                createTaskSla(config, sysId, req.taskSlaDueDate());
            }
        }

        String url = config.baseUrl() + "/incident.do?sys_id=" + sysId;
        return new ServiceNowIncidentResponse(
                incidentNumber,
                sysId,
                url,
                "created",
                "Incident " + incidentNumber + " created successfully in ServiceNow"
        );
    }

    /**
     * Links all CIs in the group to the incident via the {@code task_ci} M2M table.
     * The first CI is already set via {@code cmdb_ci}; this adds all of them for completeness.
     */
    private void linkAdditionalCis(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentSysId,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        String endpoint = config.baseUrl() + "/api/now/table/task_ci";
        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        for (CreateServiceNowIncidentRequest.AffectedAsset asset : groupAssets) {
            String ciSysId = extractCiSysId(asset.assetIdentifier());
            if (ciSysId == null) continue;

            Map<String, Object> taskCiPayload = new LinkedHashMap<>();
            taskCiPayload.put("task", incidentSysId);
            taskCiPayload.put("ci_item", ciSysId);

            try {
                String body = objectMapper.writeValueAsString(taskCiPayload);
                HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
                outboundHttpClient.exchange(
                        endpoint,
                        HttpMethod.POST,
                        requestEntity,
                        String.class,
                        "ServiceNow task_ci association",
                        outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                        context -> new OutboundFailureDecision<>(
                                false,
                                0L,
                                context.error() instanceof RuntimeException rte ? rte
                                        : new RuntimeException(context.error().getMessage(), context.error())
                        )
                );
            } catch (Exception e) {
                log.warn("Failed to associate CI {} with incident {}: {}", ciSysId, incidentSysId, e.getMessage());
            }
        }
    }

    /**
     * Creates a Task SLA record in ServiceNow linking the incident to a remediation target date.
     * Uses the {@code task_sla} table. Best-effort — failures are logged and do not abort incident creation.
     */
    private void createTaskSla(
            ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config,
            String incidentSysId,
            String dueDateYmd
    ) {
        String endpoint = config.baseUrl() + "/api/now/table/task_sla";
        HttpHeaders headers = buildHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        // Target date: YYYY-MM-DD 00:00:00 (ServiceNow datetime format)
        String targetDate = dueDateYmd.trim() + " 00:00:00";

        Map<String, Object> slaPayload = new LinkedHashMap<>();
        slaPayload.put("task", incidentSysId);
        slaPayload.put("target_date", targetDate);
        slaPayload.put("planned_end_date", targetDate);
        // Stage: in_progress so it appears as an active SLA commitment
        slaPayload.put("stage", "in_progress");

        try {
            String body = objectMapper.writeValueAsString(slaPayload);
            HttpEntity<String> requestEntity = new HttpEntity<>(body, headers);
            outboundHttpClient.exchange(
                    endpoint,
                    HttpMethod.POST,
                    requestEntity,
                    String.class,
                    "ServiceNow task_sla creation",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<>(
                            false,
                            0L,
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException(context.error().getMessage(), context.error())
                    )
            );
            log.info("Created task_sla for incident {} with target date {}", incidentSysId, targetDate);
        } catch (Exception e) {
            log.warn("Failed to create task_sla for incident {}: {}", incidentSysId, e.getMessage());
        }
    }

    /** Updates findings for the given components and CVE with the incident number. */
    private void linkFindingsToIncident(
            String cveId,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets,
            String incidentNumber
    ) {
        List<UUID> componentIds = groupAssets.stream()
                .map(a -> {
                    try { return UUID.fromString(a.componentId()); } catch (Exception e) { return null; }
                })
                .filter(id -> id != null)
                .collect(Collectors.toList());

        if (componentIds.isEmpty()) return;

        List<Finding> findings = findingRepository.findByComponentIdInAndVulnerabilityCveId(componentIds, cveId);
        for (Finding f : findings) {
            f.setIncidentId(incidentNumber);
            f.touch();
        }
        if (!findings.isEmpty()) {
            findingRepository.saveAll(findings);
        }
    }

    private Map<String, Object> buildPayload(
            String cveId,
            CreateServiceNowIncidentRequest req,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        int priority = PRIORITY_MAP.getOrDefault(
                req.priority() != null ? req.priority().toUpperCase(Locale.ROOT) : "MEDIUM",
                3
        );

        String softwareLabel = deriveSoftwareLabel(groupAssets);
        String shortDescription = cveId + ": " + softwareLabel + ": Fix";
        String description = buildDescription(cveId, req, groupAssets);
        String workNotes = buildWorkNotes(cveId, req, effectiveAssignmentGroup, groupAssets);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("short_description", shortDescription);
        payload.put("description", description);
        payload.put("work_notes", workNotes);
        payload.put("priority", String.valueOf(priority));
        payload.put("urgency", String.valueOf(Math.min(3, priority)));
        payload.put("impact", String.valueOf(Math.min(3, priority)));
        payload.put("category", "Security");
        payload.put("subcategory", "Vulnerability");

        // Assignment group (always set — falls back to default)
        payload.put("assignment_group", effectiveAssignmentGroup);
        String assignedTo = req.assignedTo();
        if (assignedTo != null && !assignedTo.isBlank()) {
            payload.put("assigned_to", assignedTo.trim());
        }

        // Due date
        if (req.dueDate() != null && !req.dueDate().isBlank()) {
            payload.put("due_date", req.dueDate().trim() + " 00:00:00");
        }

        // Resolution notes: patch / fix information
        if (req.solutionInfo() != null && !req.solutionInfo().isBlank()) {
            payload.put("close_notes", req.solutionInfo().trim());
        }

        // Primary CI reference — first asset's sys_id (cmdb_ci resolves by sys_id in ServiceNow)
        String primaryCiSysId = groupAssets.stream()
                .map(a -> extractCiSysId(a.assetIdentifier()))
                .filter(id -> id != null)
                .findFirst()
                .orElse(null);
        if (primaryCiSysId != null) {
            payload.put("cmdb_ci", primaryCiSysId);
        }

        // Scout metadata custom fields
        payload.put("u_scout_cve_id", cveId);
        payload.put("u_scout_severity", req.severity() != null ? req.severity() : "");
        payload.put("u_scout_cvss_score", req.cvssScore() != null ? String.valueOf(req.cvssScore()) : "");
        payload.put("u_scout_kev", req.inKev() ? "true" : "false");

        return payload;
    }

    /**
     * Extracts the ServiceNow CI sys_id from an assetIdentifier.
     * Handles identifiers with a {@code ci:} prefix (e.g. {@code ci:0da9a80d3790...} → {@code 0da9a80d3790...}).
     */
    private String extractCiSysId(String assetIdentifier) {
        if (assetIdentifier == null || assetIdentifier.isBlank()) return null;
        String trimmed = assetIdentifier.trim();
        if (trimmed.startsWith("ci:")) {
            String sysId = trimmed.substring(3).trim();
            return sysId.isBlank() ? null : sysId;
        }
        // If it looks like a bare sys_id (32 hex chars), use it directly
        if (trimmed.matches("[0-9a-fA-F]{32}")) {
            return trimmed;
        }
        return null;
    }

    /** Returns a comma-separated list of distinct package names found in the asset group. */
    private String deriveSoftwareLabel(List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets) {
        List<String> names = groupAssets.stream()
                .map(CreateServiceNowIncidentRequest.AffectedAsset::packageName)
                .filter(n -> n != null && !n.isBlank())
                .distinct()
                .collect(Collectors.toList());
        if (names.isEmpty()) return "Unknown Software";
        return String.join(", ", names);
    }

    private String buildDescription(
            String cveId,
            CreateServiceNowIncidentRequest req,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("VULNERABILITY DETAILS\n");
        sb.append("=====================\n");
        sb.append("CVE ID       : ").append(cveId).append("\n");
        if (req.severity() != null) {
            sb.append("Severity     : ").append(req.severity()).append("\n");
        }
        if (req.cvssScore() != null) {
            sb.append("CVSS v3 Score: ").append(req.cvssScore()).append("\n");
        }
        if (req.epssScore() != null) {
            sb.append("EPSS Score   : ").append(String.format("%.1f%%", req.epssScore() * 100)).append("\n");
        }
        if (req.inKev()) {
            sb.append("CISA KEV     : YES — actively exploited, remediation required\n");
        }
        if (req.findingTitle() != null && !req.findingTitle().isBlank()) {
            sb.append("\nFINDING\n");
            sb.append("=======\n");
            sb.append(req.findingTitle().trim()).append("\n");
        }

        // Affected CIs — name with CI identifier so responders can look up in CMDB
        if (!groupAssets.isEmpty()) {
            sb.append("\nAFFECTED ASSETS (").append(groupAssets.size()).append(")\n");
            sb.append("================").append("=".repeat(String.valueOf(groupAssets.size()).length() + 3)).append("\n");
            for (CreateServiceNowIncidentRequest.AffectedAsset asset : groupAssets) {
                sb.append("  • ");
                if (asset.assetName() != null && !asset.assetName().isBlank()) {
                    sb.append(asset.assetName());
                }
                // Always include the CI identifier so responders can cross-reference CMDB
                if (asset.assetIdentifier() != null && !asset.assetIdentifier().isBlank()) {
                    sb.append(" (").append(asset.assetIdentifier()).append(")");
                }
                if (asset.packageName() != null) {
                    sb.append(" — ").append(asset.packageName());
                    if (asset.packageVersion() != null && !asset.packageVersion().isBlank()) {
                        sb.append(" ").append(asset.packageVersion());
                    }
                }
                sb.append("\n");
            }
        }

        if (req.dueDate() != null && !req.dueDate().isBlank()) {
            sb.append("\nREMEDIATION TARGET: ").append(req.dueDate()).append("\n");
        }

        // Solution / remediation guidance in the description body
        if (req.solutionInfo() != null && !req.solutionInfo().isBlank()) {
            sb.append("\nREMEDIATION PLAN\n");
            sb.append("================\n");
            sb.append(req.solutionInfo().trim()).append("\n");
        }

        if (req.notes() != null && !req.notes().isBlank()) {
            sb.append("\nANALYST NOTES\n");
            sb.append("=============\n");
            sb.append(req.notes().trim()).append("\n");
        }
        return sb.toString();
    }

    private String buildWorkNotes(
            String cveId,
            CreateServiceNowIncidentRequest req,
            String effectiveAssignmentGroup,
            List<CreateServiceNowIncidentRequest.AffectedAsset> groupAssets
    ) {
        StringBuilder sb = new StringBuilder();
        sb.append("Scout Finding — created automatically by Scout vulnerability management platform.\n\n");
        sb.append("CVE: ").append(cveId).append("\n");
        if (req.priority() != null) sb.append("Priority: ").append(req.priority()).append("\n");
        sb.append("Assignment Group: ").append(effectiveAssignmentGroup).append("\n");

        if (!groupAssets.isEmpty()) {
            sb.append("\nAffected CIs:\n");
            groupAssets.forEach(a -> {
                sb.append("  • ");
                if (a.assetName() != null && !a.assetName().isBlank()) {
                    sb.append(a.assetName());
                }
                if (a.assetIdentifier() != null && !a.assetIdentifier().isBlank()) {
                    sb.append(" (").append(a.assetIdentifier()).append(")");
                }
                sb.append("\n");
            });
            sb.append("\nAffected component IDs:\n");
            groupAssets.forEach(a -> sb.append("  ").append(a.componentId()).append("\n"));
        }

        if (req.solutionInfo() != null && !req.solutionInfo().isBlank()) {
            sb.append("\nREMEDIATION / SOLUTION\n");
            sb.append("======================\n");
            sb.append(req.solutionInfo().trim()).append("\n");
        }

        return sb.toString();
    }

    /**
     * Fetches the list of active assignment group names from ServiceNow's sys_user_group table.
     * Returns an empty list if ServiceNow is not configured or the call fails.
     */
    public List<String> listAssignmentGroups(Tenant tenant) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config =
                serviceNowCmdbConfigService.resolveRuntimeConfig(tenant).orElse(null);
        if (config == null) {
            log.debug("ServiceNow not configured, skipping assignment group fetch");
            return List.of();
        }
        try {
            String url = config.baseUrl().replaceAll("/+$", "")
                    + "/api/now/table/sys_user_group"
                    + "?sysparm_fields=name,description"
                    + "&sysparm_query=active%3Dtrue"
                    + "&sysparm_limit=500"
                    + "&sysparm_display_value=true"
                    + "&sysparm_exclude_reference_link=true";
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(buildHeaders(config)),
                    String.class,
                    "ServiceNow sys_user_group",
                    outboundPolicyFactory.forProvider("servicenow", 0L, null, null),
                    context -> new OutboundFailureDecision<>(context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException re ? re : new RuntimeException(context.error()))
            );
            if (!response.getStatusCode().is2xxSuccessful() || response.getBody() == null) {
                return List.of();
            }
            JsonNode root = objectMapper.readTree(response.getBody());
            JsonNode results = root.path("result");
            if (!results.isArray()) return List.of();
            List<String> groups = new ArrayList<>();
            for (JsonNode node : results) {
                String name = node.path("name").asText(null);
                if (name != null && !name.isBlank()) groups.add(name);
            }
            groups.sort(String.CASE_INSENSITIVE_ORDER);
            return groups;
        } catch (Exception e) {
            log.warn("Failed to fetch assignment groups from ServiceNow: {}", e.getMessage());
            return List.of();
        }
    }

    private HttpHeaders buildHeaders(ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config) {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        if (config.authType() == ServiceNowAuthType.BEARER) {
            headers.setBearerAuth(config.credentialSecret());
        } else {
            headers.setBasicAuth(
                    config.username() != null ? config.username() : "",
                    config.credentialSecret() != null ? config.credentialSecret() : "",
                    StandardCharsets.UTF_8
            );
        }
        return headers;
    }
}
