package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.asAnalyst;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Smoke test that proves the {@link PostgresControllerIntegrationTest}
 * scaffolding boots, applies the API-key property, and the {@link
 * com.prototype.vulnwatch.support.AuthRequest} helper authenticates correctly.
 *
 * <p>Intentionally tiny: {@code AuthContextController} itself is already at
 * 100% coverage. The point is to exercise the new test pattern end-to-end.
 */
@PostgresControllerIntegrationTest
class AuthContextControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("auth_context_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    void authContextRequiresApiKey() throws Exception {
        mockMvc.perform(get("/api/auth/context"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authContextWithApiKeyReturnsAnonymousActor() throws Exception {
        mockMvc.perform(authedGet("/api/auth/context"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(false))
                .andExpect(jsonPath("$.entitlements").isMap());
    }

    @Test
    void meAliasUsesUserIdFromHeader() throws Exception {
        mockMvc.perform(asAnalyst(authedGet("/api/me")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(PostgresITSupport.DEFAULT_USER_ID));
    }
}
