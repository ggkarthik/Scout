package com.prototype.vulnwatch.security;

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
        "spring.datasource.url=jdbc:h2:mem:api-security-no-creator;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password="
})
@AutoConfigureMockMvc
class ApiSecurityWithoutCreatorKeyIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void operationsDashboardAllowsApiKeyWhenCreatorKeyIsNotConfigured() throws Exception {
        mockMvc.perform(get("/api/operations/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());
    }

    @Test
    void authContextDefaultsToCreatorWhenCreatorKeyIsNotConfigured() throws Exception {
        mockMvc.perform(get("/api/auth/context").header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(true));
    }
}
