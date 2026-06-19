package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asAnalyst;
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

@PostgresControllerIntegrationTest
class UpgradeRecommendationControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("upgrade_recommendation_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void upgradeRecommendationCanBeRequested() throws Exception {
        mockMvc.perform(asAnalyst(authedPost("/api/upgrade-recommendation")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "softwareName": "nginx",
                                  "vendor": "nginx",
                                  "currentVersion": "1.20.0",
                                  "cveIds": ["CVE-2024-0001"]
                                }
                                """)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.recommendedVersion").isString())
                .andExpect(jsonPath("$.upgradeNotes").isString())
                .andExpect(jsonPath("$.urgency").isString());
    }
}
