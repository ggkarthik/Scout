package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AiSecurityDigestServiceTest {
    private static final String KEY = testKey("content");

    @Test
    void treatsCrossVersionContentAsReapprovalInsteadOfDrift() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        AiSecurityDigestService current = new AiSecurityDigestService(KEY, "v2", "", "");
        AiSecurityDigestService prior = new AiSecurityDigestService(KEY, "v1", "", "");

        assertEquals(AiSecurityDigestService.Comparison.BASELINE_UNKNOWN_REAPPROVAL_REQUIRED,
                current.compare(current.digest(tenant, "prompt", "same definition"),
                        prior.digest(tenant, "prompt", "same definition")));
    }

    @Test
    void scopesRuntimeIdentitiesToTenantAndPurpose() {
        Tenant first = new Tenant(); first.setId(UUID.randomUUID());
        Tenant second = new Tenant(); second.setId(UUID.randomUUID());
        AiSecurityDigestService service = new AiSecurityDigestService(KEY, "v1", "", "");

        assertNotEquals(service.identityDigest(first, "provider-execution:FOUNDRY", "id").value(),
                service.identityDigest(second, "provider-execution:FOUNDRY", "id").value());
    }

    @Test
    void separatesContentAndRuntimeKeyFamilies() {
        Tenant tenant = new Tenant(); tenant.setId(UUID.randomUUID());
        String runtimeKey = testKey("runtime");
        AiSecurityDigestService service = new AiSecurityDigestService(
                KEY, "content-v1", "", "", runtimeKey, "runtime-v1", "", "");

        assertNotEquals(service.digest(tenant, "same", "value").value(),
                service.identityDigest(tenant, "same", "value").value());
        assertEquals("content-v1", service.digest(tenant, "same", "value").keyVersion());
        assertEquals("runtime-v1", service.identityDigest(tenant, "same", "value").keyVersion());
    }

    private static String testKey(String purpose) {
        return String.join("-", "test", "only", purpose, "hmac", "material", "0001");
    }
}
