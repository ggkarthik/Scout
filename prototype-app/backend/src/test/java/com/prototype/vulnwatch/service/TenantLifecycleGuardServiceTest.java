package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.Tenant;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

class TenantLifecycleGuardServiceTest {

    private final TenantLifecycleGuardService service = new TenantLifecycleGuardService();

    @Test
    void onlyActiveTenantsAreAccessible() {
        Tenant active = tenant("ACTIVE");
        Tenant provisioning = tenant("PROVISIONING");
        Tenant failed = tenant("PROVISIONING_FAILED");

        assertTrue(service.isTenantAccessible(active));
        assertFalse(service.isTenantAccessible(provisioning));
        assertFalse(service.isTenantAccessible(failed));
        assertThrows(ResponseStatusException.class, () -> service.assertTenantAccessible(provisioning));
        assertThrows(ResponseStatusException.class, () -> service.assertTenantAccessible(failed));
    }

    private Tenant tenant(String status) {
        Tenant tenant = new Tenant();
        tenant.setStatus(status);
        return tenant;
    }
}
