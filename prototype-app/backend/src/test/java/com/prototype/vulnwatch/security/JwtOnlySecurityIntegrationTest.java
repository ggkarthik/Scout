package com.prototype.vulnwatch.security;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.DashboardController;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.DashboardService;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = DashboardController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "app.security.allow-api-key-auth=false",
                "spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class JwtOnlySecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TenantService tenantService;
    @MockBean
    private TenantRepository tenantRepository;
    @MockBean
    private WorkspaceService workspaceService;
    @MockBean
    private DashboardService dashboardService;
    @MockBean
    private OperationalMetricsService operationalMetricsService;
    @MockBean
    private JwtDecoder jwtDecoder;
    @MockBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;
    @MockBean
    private TenantSupportGrantService tenantSupportGrantService;

    @Test
    void rejectsApiKeyWhenJwtOnlyModeIsEnabled() throws Exception {
        mockMvc.perform(get("/api/dashboard").header("X-API-Key", "test-api-key"))
                .andExpect(status().isUnauthorized());
    }
}
