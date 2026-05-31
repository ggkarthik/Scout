package com.prototype.vulnwatch.controller;

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
 * Controller-layer integration tests for the Phase 3 investigation analysis endpoints.
 * Verifies HTTP contract, empty-inventory fallback, and auth requirements.
 */
@PostgresControllerIntegrationTest
class InvestigationAnalysisControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("investigation_analysis_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    // -------------------------------------------------------------------------
    // resolve-inventory
    // -------------------------------------------------------------------------

    @Test
    void resolveInventoryReturnsEmptyWhenNoCriteriaProvided() throws Exception {
        String body = """
                {"criteria": []}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99001/investigation/resolve-inventory")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resolved").isArray())
                .andExpect(jsonPath("$.resolved").isEmpty())
                .andExpect(jsonPath("$.totalAssets").value(0));
    }

    @Test
    void resolveInventoryReturnsEmptyWhenNoInventoryMatchFound() throws Exception {
        String body = """
                {"criteria": [
                  {"id": "c1", "software": "nonexistent-pkg-xyz", "version": "1.0.0", "vendor": ""}
                ]}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99002/investigation/resolve-inventory")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resolved").isArray())
                .andExpect(jsonPath("$.totalAssets").value(0));
    }

    @Test
    void resolveInventoryRequiresAuthentication() throws Exception {
        mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/cve-detail/CVE-2024-99003/investigation/resolve-inventory")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"criteria\":[]}"))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------------------------------
    // false-positive-analysis
    // -------------------------------------------------------------------------

    @Test
    void fpAnalysisReturnsEmptyWhenNoCriteriaAndNoCorrelationData() throws Exception {
        String body = """
                {"criteria": []}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99010/investigation/false-positive-analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.results").isArray())
                .andExpect(jsonPath("$.results").isEmpty());
    }

    @Test
    void fpAnalysisReturnsFallbackRowWhenNoDbCorrelationExists() throws Exception {
        String body = """
                {"criteria": [
                  {"id": "c1", "software": "openssl", "version": "1.1.1", "vendor": ""}
                ]}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99011/investigation/false-positive-analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.results").isArray())
                // No correlation in DB → fallback criteria-based row
                .andExpect(jsonPath("$.results[0].software").value("openssl"))
                .andExpect(jsonPath("$.results[0].falsePositive").value(false))
                .andExpect(jsonPath("$.results[0].statusTone").value("waiting"));
    }

    @Test
    void fpAnalysisRequiresAuthentication() throws Exception {
        mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/cve-detail/CVE-2024-99012/investigation/false-positive-analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"criteria\":[]}"))
                .andExpect(status().isUnauthorized());
    }

    // -------------------------------------------------------------------------
    // eol-analysis
    // -------------------------------------------------------------------------

    @Test
    void eolAnalysisReturnsEmptyWhenNoCriteriaProvided() throws Exception {
        String body = """
                {"criteria": []}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99020/investigation/eol-analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.results").isArray())
                .andExpect(jsonPath("$.results").isEmpty());
    }

    @Test
    void eolAnalysisReturnsFallbackRowWhenNoInventoryMatch() throws Exception {
        String body = """
                {"criteria": [
                  {"id": "c1", "software": "nonexistent-pkg-abc", "version": "2.0", "vendor": "Acme"}
                ]}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99021/investigation/eol-analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.results").isArray())
                // No inventory match → fallback row with lifecycle=Unknown
                .andExpect(jsonPath("$.results[0].software").value("nonexistent-pkg-abc"))
                .andExpect(jsonPath("$.results[0].lifecycle").value("Unknown"))
                .andExpect(jsonPath("$.results[0].endOfLife").value("—"));
    }

    @Test
    void eolAnalysisRequiresAuthentication() throws Exception {
        mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/cve-detail/CVE-2024-99022/investigation/eol-analysis")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"criteria\":[]}"))
                .andExpect(status().isUnauthorized());
    }
}
