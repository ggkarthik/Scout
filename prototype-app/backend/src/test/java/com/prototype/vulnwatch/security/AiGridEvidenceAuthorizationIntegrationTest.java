package com.prototype.vulnwatch.security;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.aisecurity.controller.AiGridController;
import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.config.ApiKeyAuthenticationFilter;
import com.prototype.vulnwatch.config.RequestCorrelationFilter;
import com.prototype.vulnwatch.config.SecurityConfig;
import com.prototype.vulnwatch.controller.ApiExceptionHandler;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.AuthenticatedTenantActor;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.OperationalMetricsService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

@WebMvcTest(controllers = AiGridController.class,
        excludeAutoConfiguration = UserDetailsServiceAutoConfiguration.class,
        properties = {"spring.mvc.throw-exception-if-no-handler-found=true",
                "spring.web.resources.add-mappings=false"})
@Import({SecurityConfig.class, ApiKeyAuthenticationFilter.class, RequestCorrelationFilter.class,
        ApiExceptionHandler.class, RequestActorService.class})
class AiGridEvidenceAuthorizationIntegrationTest {
    @Autowired private MockMvc mockMvc;
    @MockBean private TenantService tenantService;
    @MockBean private TenantRepository tenantRepository;
    @MockBean private WorkspaceService workspaceService;
    @MockBean private AiSecurityAccessService accessService;
    @MockBean private AiGridApiService apiService;
    @MockBean private JwtDecoder jwtDecoder;
    @MockBean private JwtTenantAuthenticationService jwtAuthentication;
    @MockBean private TenantSupportGrantService tenantSupportGrantService;
    @MockBean private OperationalMetricsService operationalMetricsService;

    private Tenant tenant;
    private UUID tenantId;

    @BeforeEach
    void setUp() {
        tenantId = UUID.randomUUID();
        tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("AI Grid tenant");
        tenant.setStatus("ACTIVE");
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(apiService.systemFacts(any(), any())).thenReturn(List.of());
    }

    @Test
    void operatorCannotReadGovernedEvidenceFacts() throws Exception {
        authenticate("operator.jwt", "operator", "OPERATOR");
        mockMvc.perform(get("/api/ai-systems/{id}/facts", UUID.randomUUID())
                        .header("Authorization", "Bearer operator.jwt"))
                .andExpect(status().isForbidden());
    }

    @Test
    void readOnlyAuditorCanReadGovernedEvidenceFacts() throws Exception {
        authenticate("auditor.jwt", "auditor", "READ_ONLY_AUDITOR");
        mockMvc.perform(get("/api/ai-systems/{id}/facts", UUID.randomUUID())
                        .header("Authorization", "Bearer auditor.jwt"))
                .andExpect(status().isOk());
    }

    private void authenticate(String token, String userId, String role) {
        Jwt jwt = Jwt.withTokenValue(token).header("alg", "none").subject(userId)
                .claim("roles", List.of(role)).build();
        when(jwtDecoder.decode(token)).thenReturn(jwt);
        when(jwtAuthentication.authenticate(eq(jwt), anyString())).thenReturn(new AuthenticatedTenantActor(
                userId, UUID.randomUUID(), userId + "@example.com", userId, tenantId,
                "AI Grid tenant", null, Set.of(role)));
    }
}
