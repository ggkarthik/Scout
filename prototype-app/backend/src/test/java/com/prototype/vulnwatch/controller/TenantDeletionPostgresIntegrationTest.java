package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedDelete;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

@PostgresControllerIntegrationTest
@TestPropertySource(properties = "app.security.jwt.hmac-secret=0123456789abcdef0123456789abcdef")
class TenantDeletionPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("tenant_deletion_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private TenantMembershipRepository tenantMembershipRepository;

    @Autowired
    @Qualifier("platformJdbcTemplate")
    private JdbcTemplate platformJdbcTemplate;

    @Test
    void deletingTenantDropsSchemaRevokesMembershipAndBlocksFurtherAccess() throws Exception {
        Tenant tenant = tenantService.createTenant(
                "15June_Demo_Enterprise",
                "15june-demo-enterprise",
                "ENTERPRISE",
                null
        );
        tenantSchemaMigrationService.provisionNewTenant(tenant);

        String subject = "tenant-owner-" + UUID.randomUUID();
        String email = "tenant.owner+" + UUID.randomUUID() + "@example.com";
        String password = "DeleteMe123!";
        AppUser user = createTenantUser(subject, email, password);
        createMembership(tenant, user, "TENANT_ADMIN");

        String token = login(email, password);

        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.tenantName").value("15June_Demo_Enterprise"));

        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        mockMvc.perform(asPlatformOwner(authedDelete("/api/platform/tenants/{tenantId}", tenant.getId())))
                .andExpect(status().isNoContent());

        assertTrue(tenantRepository.findById(tenant.getId()).isEmpty());
        assertSchemaMissing(tenant.getSchemaName());
        assertTrue(tenantMembershipRepository
                .findFirstByUserExternalSubjectAndTenantId(subject, tenant.getId())
                .isEmpty());

        AppUser scrubbedUser = appUserRepository.findById(user.getId()).orElseThrow();
        assertNull(scrubbedUser.getPasswordHash());
        assertNull(scrubbedUser.getPasswordSetAt());
        assertEquals("INACTIVE", scrubbedUser.getStatus());

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isUnauthorized());

        mockMvc.perform(get("/api/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().is4xxClientError());

        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isForbidden());
    }

    private AppUser createTenantUser(String subject, String email, String password) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        user.setEmail(email);
        user.setDisplayName("Tenant Owner");
        user.setStatus("ACTIVE");
        user.setPasswordHash(BCrypt.hashpw(password, BCrypt.gensalt(10)));
        user.setPasswordSetAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        return appUserRepository.save(user);
    }

    private void createMembership(Tenant tenant, AppUser user, String role) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        membership.setUpdatedAt(Instant.now());
        tenantMembershipRepository.save(membership);
    }

    private String login(String email, String password) throws Exception {
        String response = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "email": "%s",
                                  "password": "%s"
                                }
                                """.formatted(email, password)))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return JsonPath.read(response, "$.token");
    }

    private void assertSchemaMissing(String schemaName) {
        Integer count = platformJdbcTemplate.queryForObject("""
                select count(*)
                from information_schema.schemata
                where schema_name = ?
                """, Integer.class, schemaName);
        assertEquals(0, count);
    }
}
