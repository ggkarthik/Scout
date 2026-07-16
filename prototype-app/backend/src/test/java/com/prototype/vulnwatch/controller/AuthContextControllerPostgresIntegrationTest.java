package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.asAnalyst;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantSupportGrantRepository;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

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
    private static final String JWT_SECRET = "phase-1-local-auth-secret-32-bytes";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("APP_JWT_HMAC_SECRET", () -> JWT_SECRET);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    private TenantSupportGrantRepository tenantSupportGrantRepository;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Test
    void authContextRequiresApiKey() throws Exception {
        mockMvc.perform(get("/api/auth/context"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void authContextWithApiKeyReturnsAnonymousActor() throws Exception {
        mockMvc.perform(authedGet("/api/auth/context"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.creator").value(false));
    }

    @Test
    void meAliasUsesUserIdFromHeader() throws Exception {
        mockMvc.perform(asAnalyst(authedGet("/api/me")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value(PostgresITSupport.DEFAULT_USER_ID));
    }

    @Test
    void tenantScopedLoginReturnsSingleAllowedTenantMembership() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser user = saveUser("tenant.admin.auth-context@example.com", false, "password-123");
        tenantMembershipRepository.save(activeMembership(user, tenant, "TENANT_ADMIN"));

        String token = login("tenant.admin.auth-context@example.com", "password-123");

        mockMvc.perform(get("/api/auth/context")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("tenant.admin.auth-context@example.com"))
                .andExpect(jsonPath("$.tenantId").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.tenantName").value(tenant.getName()))
                .andExpect(jsonPath("$.platformScope").value(false))
                .andExpect(jsonPath("$.actingAsPlatformOwner").value(false))
                .andExpect(jsonPath("$.allowedTenants.length()").value(1))
                .andExpect(jsonPath("$.allowedTenants[0].id").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.allowedTenants[0].role").value("TENANT_ADMIN"))
                .andExpect(jsonPath("$.allowedTenants[0].accessMode").doesNotExist())
                .andExpect(jsonPath("$.supportAccessMode").doesNotExist());
    }

    @Test
    void platformOwnerContextSwitchSurfacesGrantScopedTenantAccess() throws Exception {
        AppUser owner = saveUser("platform.owner.auth-context@example.com", true, "password-123");
        Tenant supportTenant = tenantService.createTenant(
                "Support Customer", "support-customer", "ENTERPRISE", null);
        tenantSchemaMigrationService.provisionNewTenant(supportTenant);
        tenantSupportGrantRepository.save(activeGrant(owner, supportTenant, "READ_ONLY"));

        String platformToken = login("platform.owner.auth-context@example.com", "password-123");

        mockMvc.perform(get("/api/auth/context")
                        .header("Authorization", "Bearer " + platformToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").doesNotExist())
                .andExpect(jsonPath("$.platformScope").value(true))
                .andExpect(jsonPath("$.actingAsPlatformOwner").value(false))
                .andExpect(jsonPath("$.allowedTenants.length()").value(1))
                .andExpect(jsonPath("$.allowedTenants[0].id").value(supportTenant.getId().toString()))
                .andExpect(jsonPath("$.allowedTenants[0].role").value("PLATFORM_OWNER"))
                .andExpect(jsonPath("$.allowedTenants[0].accessMode").value("READ_ONLY"));

        String tenantToken = switchTenantContext(platformToken, supportTenant.getId());

        mockMvc.perform(get("/api/auth/context")
                        .header("Authorization", "Bearer " + tenantToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(supportTenant.getId().toString()))
                .andExpect(jsonPath("$.tenantName").value("Support Customer"))
                .andExpect(jsonPath("$.platformScope").value(false))
                .andExpect(jsonPath("$.actingAsPlatformOwner").value(true))
                .andExpect(jsonPath("$.supportAccessMode").value("READ_ONLY"))
                .andExpect(jsonPath("$.allowedTenants.length()").value(1))
                .andExpect(jsonPath("$.allowedTenants[0].id").value(supportTenant.getId().toString()))
                .andExpect(jsonPath("$.allowedTenants[0].accessMode").value("READ_ONLY"));

        String clearedToken = clearTenantContext(tenantToken);

        mockMvc.perform(get("/api/auth/context")
                        .header("Authorization", "Bearer " + clearedToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").doesNotExist())
                .andExpect(jsonPath("$.platformScope").value(true))
                .andExpect(jsonPath("$.actingAsPlatformOwner").value(false))
                .andExpect(jsonPath("$.supportAccessMode").doesNotExist());
    }

    private String login(String email, String password) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isOk())
                .andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private String switchTenantContext(String token, UUID tenantId) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/tenant-context")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "tenantId": "%s"
                                }
                                """.formatted(tenantId)))
                .andExpect(status().isOk())
                .andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private String clearTenantContext(String token) throws Exception {
        MvcResult result = mockMvc.perform(delete("/api/auth/tenant-context")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private AppUser saveUser(String subject, boolean platformOwner, String password) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        user.setEmail(subject);
        user.setDisplayName(subject);
        user.setPlatformOwner(platformOwner);
        user.setPasswordHash(BCrypt.hashpw(password, BCrypt.gensalt(10)));
        user.setPasswordSetAt(Instant.now());
        user.setStatus("ACTIVE");
        return appUserRepository.save(user);
    }

    private TenantMembership activeMembership(AppUser user, Tenant tenant, String role) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        return membership;
    }

    private TenantSupportGrant activeGrant(AppUser owner, Tenant tenant, String accessMode) {
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setInvitedPlatformSubject(owner.getExternalSubject());
        grant.setReason("Auth context integration test");
        grant.setScope("Tenant user-management validation");
        grant.setAccessMode(accessMode);
        grant.setStatus("ACTIVE");
        grant.setGrantedBy(owner);
        grant.setAcceptedBy(owner);
        grant.setRequestedAt(Instant.now());
        grant.setAcceptedAt(Instant.now());
        grant.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        grant.setUpdatedAt(Instant.now());
        return grant;
    }

}
