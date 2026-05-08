package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.controller.AuthController;
import com.prototype.vulnwatch.dto.AuthSessionResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ValidationAuthService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(
        controllers = AuthController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {
                "app.security.api-key=test-api-key",
                "app.security.allow-api-key-auth=false"
        })
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class, ApiExceptionHandler.class, RequestActorService.class})
class AuthControllerSecurityIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private TenantService tenantService;
    @MockBean
    private TenantRepository tenantRepository;
    @MockBean
    private WorkspaceService workspaceService;
    @MockBean
    private ValidationAuthService validationAuthService;
    @MockBean
    private OperationalMetricsService operationalMetricsService;
    @MockBean
    private JwtDecoder jwtDecoder;
    @MockBean
    private JwtTenantAuthenticationService jwtTenantAuthenticationService;

    @Test
    void loginIsPublicEvenWhenApiKeysAreDisabled() throws Exception {
        when(validationAuthService.login(any(), any())).thenReturn(new AuthSessionResponse("token", "Bearer", Instant.now().plusSeconds(3600)));

        mockMvc.perform(post("/api/auth/login")
                        .contentType("application/json")
                        .content("{\"email\":\"alex@example.com\",\"password\":\"correct horse battery\"}"))
                .andExpect(status().isOk());
    }
}
