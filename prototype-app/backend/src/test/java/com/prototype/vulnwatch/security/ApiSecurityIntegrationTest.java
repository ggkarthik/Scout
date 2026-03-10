package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.AuthContextController;
import com.prototype.vulnwatch.controller.DashboardController;
import com.prototype.vulnwatch.controller.OperationalDashboardController;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.DashboardService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.OperationalDashboardService;
import com.prototype.vulnwatch.service.TenantService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = {
                DashboardController.class,
                OperationalDashboardController.class,
                AuthContextController.class
        },
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
        "app.security.api-key=test-api-key",
        "app.security.creator-key=test-creator-key",
        "spring.mvc.throw-exception-if-no-handler-found=true",
        "spring.web.resources.add-mappings=false"
})
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, ApiExceptionHandler.class})
class ApiSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TenantService tenantService;

    @MockBean
    private DashboardService dashboardService;

    @MockBean
    private OperationalDashboardService operationalDashboardService;

    @MockBean
    private OperationalMetricsService operationalMetricsService;

    @BeforeEach
    void setUp() {
        when(tenantService.getDefaultTenant()).thenReturn(new Tenant());
        when(dashboardService.get(any(Tenant.class))).thenReturn(null);
        when(operationalDashboardService.get()).thenReturn(null);
    }

    @Test
    void rejectsApiRequestsWithoutKey() throws Exception {
        mockMvc.perform(get("/api/dashboard"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void acceptsApiRequestsWithKey() throws Exception {
        mockMvc.perform(get("/api/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());
    }

    @Test
    void unknownApiRouteReturnsNotFoundJson() throws Exception {
        mockMvc.perform(get("/api/tenants").header("X-API-Key", "test-api-key"))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.code").value("NOT_FOUND"))
                .andExpect(jsonPath("$.error").value("Resource not found"));
    }

    @Test
    void operationsDashboardIsForbiddenWithoutCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isForbidden());
    }

    @Test
    void operationsDashboardAllowsCreatorKey() throws Exception {
        mockMvc.perform(get("/api/operations/dashboard")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk());
    }

    @Test
    void authContextReflectsCreatorRole() throws Exception {
        mockMvc.perform(get("/api/auth/context")
                        .header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(false));

        mockMvc.perform(get("/api/auth/context")
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(true));
    }
}
