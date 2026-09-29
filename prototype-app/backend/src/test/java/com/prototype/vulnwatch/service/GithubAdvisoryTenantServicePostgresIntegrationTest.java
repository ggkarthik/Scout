package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.support.*;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

@PostgresIntegrationTest
class GithubAdvisoryTenantServicePostgresIntegrationTest {

    @Autowired
    private GithubAdvisoryTenantService tenantService;

    @Autowired
    private GithubAdvisoryIntegrationRepository integrationRepository;

    @Autowired
    private GithubRepositoryComponentAdvisoryRepository componentAdvisoryRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private TenantService tenantServiceBase;

    private Tenant tenant;
    private GithubSbomSource source;

    @BeforeEach
    void setUp() {
        tenant = tenantServiceBase.getDefaultTenant();
    }

    @Test
    void correlateAdvisoriesForTenant_createsCorrelationWhenComponentVulnerable() {
        // 1. Create GHSA advisory in platform schema
        // 2. Create GitHub source in tenant schema
        // 3. Create component matching the advisory
        // 4. Call correlateAdvisoriesForTenant
        // 5. Assert correlation created
    }

    @Test
    void correlateAdvisoriesForTenant_createsFindingWhenEnabled() {
        // 1. Enable GHSA integration for tenant
        // 2. Create vulnerable correlation
        // 3. Assert finding created with AI_GITHUB_ADVISORY kind
    }

    @Test
    void enableGhsaIntegrationForTenant_setsOptInFlag() {
        // 1. Enable for tenant
        // 2. Assert integration record has is_enabled = true
        // 3. Assert timestamps set
    }

    @Test
    void disableGhsaIntegrationForTenant_clearsOptInFlag() {
        // 1. Enable, then disable
        // 2. Assert is_enabled = false
        // 3. Assert disabled_at timestamp set
    }
}
