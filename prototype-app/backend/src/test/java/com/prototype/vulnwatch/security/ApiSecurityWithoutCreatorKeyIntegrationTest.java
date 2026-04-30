package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.AuthContextController;
import com.prototype.vulnwatch.controller.OperationalDashboardController;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OperationalDashboardResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.OperationalDashboardService;
import com.prototype.vulnwatch.service.OperationalQualityReadService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
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
                OperationalDashboardController.class,
                AuthContextController.class
        },
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
        "app.security.api-key=test-api-key",
        "spring.mvc.throw-exception-if-no-handler-found=true",
        "spring.web.resources.add-mappings=false"
})
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class ApiSecurityWithoutCreatorKeyIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private OperationalDashboardService operationalDashboardService;

    @MockBean
    private OperationalQualityReadService operationalQualityReadService;

    @MockBean
    private TenantService tenantService;

    @MockBean
    private TenantRepository tenantRepository;

    @MockBean
    private WorkspaceService workspaceService;

    @MockBean
    private OperationalMetricsService operationalMetricsService;

    @BeforeEach
    void setUp() {
        Tenant defaultTenant = new Tenant();
        defaultTenant.setId(1L);
        defaultTenant.setName("Default Workspace");
        when(tenantService.getDefaultTenant()).thenReturn(defaultTenant);
        when(workspaceService.getWorkspace()).thenReturn(defaultTenant);
        when(operationalDashboardService.get()).thenReturn(new OperationalDashboardResponse(
                Instant.EPOCH,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                List.of()
        ));
    }

    @Test
    void operationsDashboardAllowsApiKeyWhenCreatorKeyIsNotConfigured() throws Exception {
        mockMvc.perform(get("/api/operations/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk());
    }

    @Test
    void authContextDefaultsToCreatorWhenCreatorKeyIsNotConfigured() throws Exception {
        mockMvc.perform(get("/api/auth/context").header("X-API-Key", "test-api-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(true))
                .andExpect(jsonPath("$.principal").value("local-analyst"))
                .andExpect(jsonPath("$.userId").value("local-analyst"))
                .andExpect(jsonPath("$.tenantId").value("00000000-0000-0000-0000-000000000001"))
                .andExpect(jsonPath("$.tenantName").value("Default Workspace"));
    }
}
