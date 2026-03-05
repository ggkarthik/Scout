package com.prototype.vulnwatch.service;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.security.creator-key=test-creator-key",
        "spring.datasource.url=jdbc:h2:mem:ops_dashboard;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.correlation.backfill-targets-on-startup=false"
})
@AutoConfigureMockMvc
class OperationalDashboardIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void operationsDashboardExposesEndpointTimingMetrics() throws Exception {
        mockMvc.perform(get("/api/vulnerability-intelligence?page=0&size=5")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/vulnerability-intelligence/filters")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/dashboard")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/operations/dashboard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.executiveHealth.ingestionSuccessRateLast24h").isNumber())
                .andExpect(jsonPath("$.normalizationQuality.activeComponents").isNumber())
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[0].key").value("vulnerability-intelligence-list"))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[0].requestCount").value(1))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[1].key").value("vulnerability-intelligence-filters"))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[1].requestCount").value(1))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[2].key").value("dashboard-overview"))
                .andExpect(jsonPath("$.apiReadPath.endpointMetrics[2].requestCount").value(1))
                .andExpect(jsonPath("$.metricCatalog").isArray());
    }
}
