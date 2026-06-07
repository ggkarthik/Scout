package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.InvestigationRunbook;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AgentTaskMetaDto;
import com.prototype.vulnwatch.dto.InvestigationRunbookRequest;
import com.prototype.vulnwatch.dto.InvestigationRunbookResponse;
import com.prototype.vulnwatch.dto.RunbookLogEntryDto;
import com.prototype.vulnwatch.dto.RunbookLogEntryRequest;
import com.prototype.vulnwatch.dto.RunbookLogEntryResponse;
import com.prototype.vulnwatch.dto.RunbookTaskStateDto;
import com.prototype.vulnwatch.repo.InvestigationRunbookRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class InvestigationRunbookService {

    private static final TypeReference<List<RunbookTaskStateDto>> TASK_STATES_TYPE =
            new TypeReference<>() {};
    private static final TypeReference<List<RunbookLogEntryDto>> LOG_ENTRIES_TYPE =
            new TypeReference<>() {};
    private static final TypeReference<Map<String, String>> STRING_MAP_TYPE =
            new TypeReference<>() {};
    private static final TypeReference<Map<String, Object>> OBJECT_MAP_TYPE =
            new TypeReference<>() {};

    private final InvestigationRunbookRepository repository;
    private final TenantService tenantService;
    private final ObjectMapper objectMapper;

    public InvestigationRunbookService(
            InvestigationRunbookRepository repository,
            TenantService tenantService,
            ObjectMapper objectMapper) {
        this.repository = repository;
        this.tenantService = tenantService;
        this.objectMapper = objectMapper;
    }

    /** Returns empty-shell response (no DB record) if no runbook exists yet. */
    @Transactional(readOnly = true)
    public InvestigationRunbookResponse getRunbook(String cveExternalId) {
        UUID tenantId = TenantContext.getCurrentTenantId();
        return repository.findByTenantIdAndCveExternalId(tenantId, cveExternalId)
                .map(this::toResponse)
                .orElse(emptyResponse(cveExternalId));
    }

    /** Idempotent full replacement (upsert). */
    public InvestigationRunbookResponse saveRunbook(
            String cveExternalId, InvestigationRunbookRequest request) {
        UUID tenantId = TenantContext.getCurrentTenantId();
        Tenant tenant = tenantService.requireTenantUuid(tenantId);

        InvestigationRunbook runbook = repository
                .findByTenantIdAndCveExternalId(tenantId, cveExternalId)
                .orElseGet(() -> {
                    InvestigationRunbook r = new InvestigationRunbook();
                    r.setTenant(tenant);
                    r.setCveExternalId(cveExternalId);
                    return r;
                });

        if (request.taskStates() != null) {
            runbook.setTaskStatesJson(toJson(request.taskStates()));
        }
        if (request.logEntries() != null) {
            runbook.setLogEntriesJson(toJson(request.logEntries()));
        }
        if (request.leadAnalyst() != null) {
            runbook.setLeadAnalyst(request.leadAnalyst());
        }
        if (request.agentConfidence() != null) {
            runbook.setAgentConfidenceJson(toJson(request.agentConfidence()));
        }

        return toResponse(repository.save(runbook));
    }

    /** Appends a single log entry to the runbook. Creates the runbook record if absent. */
    public RunbookLogEntryResponse appendLogEntry(
            String cveExternalId, RunbookLogEntryRequest request) {
        UUID tenantId = TenantContext.getCurrentTenantId();
        Tenant tenant = tenantService.requireTenantUuid(tenantId);

        InvestigationRunbook runbook = repository
                .findByTenantIdAndCveExternalId(tenantId, cveExternalId)
                .orElseGet(() -> {
                    InvestigationRunbook r = new InvestigationRunbook();
                    r.setTenant(tenant);
                    r.setCveExternalId(cveExternalId);
                    return r;
                });

        List<RunbookLogEntryDto> entries = new ArrayList<>(
                parseLogEntries(runbook.getLogEntriesJson()));

        String entryId = UUID.randomUUID().toString();
        Instant now = Instant.now();
        String producedBy = request.producedBy() != null ? request.producedBy() : "ANALYST";
        RunbookLogEntryDto newEntry = new RunbookLogEntryDto(
                entryId,
                request.type(),
                request.message(),
                request.actor(),
                producedBy,
                now);
        entries.add(newEntry);
        runbook.setLogEntriesJson(toJson(entries));
        repository.save(runbook);

        return new RunbookLogEntryResponse(
                entryId,
                newEntry.type(),
                newEntry.message(),
                newEntry.actor(),
                newEntry.producedBy(),
                now);
    }

    /** Persists agent run metadata (confidence map + full task meta + completed task IDs) onto the runbook. */
    public void saveAgentRun(
            String cveExternalId,
            Map<String, String> confidenceMap,
            Map<String, AgentTaskMetaDto> taskMeta,
            List<String> completedTaskIds
    ) {
        UUID tenantId = TenantContext.getCurrentTenantId();
        Tenant tenant = tenantService.requireTenantUuid(tenantId);

        InvestigationRunbook runbook = repository
                .findByTenantIdAndCveExternalId(tenantId, cveExternalId)
                .orElseGet(() -> {
                    InvestigationRunbook r = new InvestigationRunbook();
                    r.setTenant(tenant);
                    r.setCveExternalId(cveExternalId);
                    return r;
                });

        runbook.setAgentConfidenceJson(toJson(confidenceMap));
        runbook.setAgentRunMetaJson(toJson(
                java.util.Map.of(
                        "taskMeta", taskMeta,
                        "completedTaskIds", completedTaskIds,
                        "ranAt", java.time.Instant.now().toString()
                )));
        repository.save(runbook);
    }

    // --- helpers ---

    private InvestigationRunbookResponse toResponse(InvestigationRunbook r) {
        return new InvestigationRunbookResponse(
                r.getId().toString(),
                r.getCveExternalId(),
                parseTaskStates(r.getTaskStatesJson()),
                parseLogEntries(r.getLogEntriesJson()),
                r.getLeadAnalyst(),
                parseStringMap(r.getAgentConfidenceJson()),
                parseObjectMap(r.getAgentSuggestionsJson()),
                r.getCreatedAt(),
                r.getUpdatedAt());
    }

    private InvestigationRunbookResponse emptyResponse(String cveExternalId) {
        return new InvestigationRunbookResponse(
                null, cveExternalId,
                Collections.emptyList(), Collections.emptyList(),
                null,
                Collections.emptyMap(), Collections.emptyMap(),
                null, null);
    }

    private List<RunbookTaskStateDto> parseTaskStates(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return objectMapper.readValue(json, TASK_STATES_TYPE);
        } catch (JsonProcessingException e) {
            return Collections.emptyList();
        }
    }

    private List<RunbookLogEntryDto> parseLogEntries(String json) {
        if (json == null || json.isBlank()) return Collections.emptyList();
        try {
            return objectMapper.readValue(json, LOG_ENTRIES_TYPE);
        } catch (JsonProcessingException e) {
            return Collections.emptyList();
        }
    }

    private Map<String, String> parseStringMap(String json) {
        if (json == null || json.isBlank()) return Collections.emptyMap();
        try {
            return objectMapper.readValue(json, STRING_MAP_TYPE);
        } catch (JsonProcessingException e) {
            return Collections.emptyMap();
        }
    }

    private Map<String, Object> parseObjectMap(String json) {
        if (json == null || json.isBlank()) return Collections.emptyMap();
        try {
            return objectMapper.readValue(json, OBJECT_MAP_TYPE);
        } catch (JsonProcessingException e) {
            return Collections.emptyMap();
        }
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Failed to serialize runbook field", e);
        }
    }
}
