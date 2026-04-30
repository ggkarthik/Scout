package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantContext;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

@ExtendWith(MockitoExtension.class)
class TenantStatusFilterTest {

    @Mock
    TenantRepository tenantRepository;

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void blocksSuspendedTenantApiRequests() throws Exception {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Acme");
        tenant.setStatus("SUSPENDED");
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        TenantContext.setCurrentTenantId(tenantId);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/dashboard");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new TenantStatusFilter(tenantRepository).doFilter(request, response, chain);

        assertEquals(423, response.getStatus());
        assertEquals("{\"code\":\"TENANT_SUSPENDED\",\"error\":\"Tenant is not active\"}", response.getContentAsString());
    }

    @Test
    void allowsPlatformRoutesForSuspendedTenants() throws Exception {
        UUID tenantId = UUID.randomUUID();
        TenantContext.setCurrentTenantId(tenantId);

        MockHttpServletRequest request = new MockHttpServletRequest("PATCH", "/api/platform/tenants/" + tenantId + "/status");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        new TenantStatusFilter(tenantRepository).doFilter(request, response, chain);

        assertEquals(200, response.getStatus());
        verify(tenantRepository, never()).findById(tenantId);
    }
}
