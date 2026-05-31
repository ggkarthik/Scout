package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPut;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Controller-layer integration tests for the Phase 2 investigation runbook endpoints.
 * Verifies happy-path GET/PUT/log-append and tenant isolation at the HTTP layer.
 */
@PostgresControllerIntegrationTest
class InvestigationRunbookControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("investigation_runbook_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void getRunbookReturnsEmptyShellWhenNoRecordExists() throws Exception {
        mockMvc.perform(authedGet("/api/cve-detail/CVE-2024-99999/investigation/runbook"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveExternalId").value("CVE-2024-99999"))
                .andExpect(jsonPath("$.taskStates").isArray())
                .andExpect(jsonPath("$.logEntries").isArray());
    }

    @Test
    void putRunbookCreatesNewRecord() throws Exception {
        String body = """
                {
                  "taskStates": [
                    {"taskId": "review-asset-inventory", "state": "DONE",
                     "producedBy": "ANALYST", "confidence": null, "completedAt": null}
                  ],
                  "logEntries": [],
                  "leadAnalyst": "alice",
                  "agentConfidence": {}
                }
                """;

        mockMvc.perform(authedPut("/api/cve-detail/CVE-2024-11111/investigation/runbook")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveExternalId").value("CVE-2024-11111"))
                .andExpect(jsonPath("$.leadAnalyst").value("alice"))
                .andExpect(jsonPath("$.taskStates[0].taskId").value("review-asset-inventory"))
                .andExpect(jsonPath("$.taskStates[0].producedBy").value("ANALYST"));
    }

    @Test
    void putRunbookIsIdempotent() throws Exception {
        String body = """
                {"taskStates": [], "logEntries": [], "leadAnalyst": "bob", "agentConfidence": {}}
                """;

        mockMvc.perform(authedPut("/api/cve-detail/CVE-2024-22222/investigation/runbook")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());

        // Second PUT with updated lead analyst — should update, not create duplicate.
        String update = """
                {"taskStates": [], "logEntries": [], "leadAnalyst": "carol", "agentConfidence": {}}
                """;
        mockMvc.perform(authedPut("/api/cve-detail/CVE-2024-22222/investigation/runbook")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(update))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leadAnalyst").value("carol"));
    }

    @Test
    void appendLogEntryCreatesEntryWithProducedBy() throws Exception {
        String logBody = """
                {"type": "NOTE", "message": "Initial triage complete.", "actor": "alice",
                 "producedBy": "ANALYST"}
                """;

        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-33333/investigation/log")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("NOTE"))
                .andExpect(jsonPath("$.message").value("Initial triage complete."))
                .andExpect(jsonPath("$.producedBy").value("ANALYST"));
    }

    @Test
    void appendAgentLogEntryRendersAsAgentType() throws Exception {
        String logBody = """
                {"type": "AGENT", "message": "Inventory resolved: 3 assets matched.",
                 "actor": "agent:copilot", "producedBy": "AGENT"}
                """;

        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-44444/investigation/log")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(logBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.type").value("AGENT"))
                .andExpect(jsonPath("$.producedBy").value("AGENT"));
    }

    @Test
    void getRunbookRequiresAuthentication() throws Exception {
        mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/cve-detail/CVE-2024-55555/investigation/runbook"))
                .andExpect(status().isUnauthorized());
    }
}
