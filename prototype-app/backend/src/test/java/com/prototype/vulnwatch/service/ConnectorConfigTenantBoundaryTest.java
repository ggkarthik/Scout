package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Connector configuration is per tenant, with no deployment-wide fallback.
 *
 * <p>ServiceNow previously resolved to {@code CMDB_SERVICENOW_BASE_URL} whenever a tenant had
 * no connector row, which pointed every unconfigured tenant at a single shared instance. These
 * tests pin the replacement behaviour: an unconfigured tenant resolves to nothing at all, and
 * two configured tenants never see each other's instance or credential.
 */
class ConnectorConfigTenantBoundaryTest {

    private final ServiceNowCmdbConfigRepository repository = mock(ServiceNowCmdbConfigRepository.class);
    private final CredentialEncryptionService credentials = mock(CredentialEncryptionService.class);

    private final ServiceNowCmdbConfigService service = new ServiceNowCmdbConfigService(
            repository,
            mock(OutboundHttpClient.class),
            new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 1, 0, 0, true, true)),
            new ObjectMapper(),
            mock(TenantQuotaService.class),
            credentials);

    @Test
    void aTenantWithoutItsOwnConnectorResolvesToNothing() {
        Tenant tenant = tenant();
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow"))
                .thenReturn(Optional.empty());

        assertTrue(service.resolveRuntimeConfig(tenant).isEmpty(),
                "an unconfigured tenant must not inherit a shared ServiceNow instance");
    }

    @Test
    void eachTenantResolvesItsOwnInstanceAndCredential() {
        Tenant tenantA = tenant();
        Tenant tenantB = tenant();
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(tenantA.getId(), "servicenow"))
                .thenReturn(Optional.of(config("https://acme.service-now.com", "acme-user", "enc-acme")));
        when(repository.findByTenant_IdAndSourceSystemIgnoreCase(tenantB.getId(), "servicenow"))
                .thenReturn(Optional.of(config("https://globex.service-now.com", "globex-user", "enc-globex")));
        when(credentials.decrypt("enc-acme")).thenReturn("acme-secret");
        when(credentials.decrypt("enc-globex")).thenReturn("globex-secret");

        var resolvedA = service.resolveRuntimeConfig(tenantA).orElseThrow();
        var resolvedB = service.resolveRuntimeConfig(tenantB).orElseThrow();

        assertEquals("https://acme.service-now.com", resolvedA.baseUrl());
        assertEquals("acme-secret", resolvedA.credentialSecret());
        assertEquals("https://globex.service-now.com", resolvedB.baseUrl());
        assertEquals("globex-secret", resolvedB.credentialSecret());
    }

    /** A tenant with no id cannot be scoped, so it must resolve to nothing rather than anything. */
    @Test
    void anUnidentifiedTenantResolvesToNothing() {
        assertTrue(service.resolveRuntimeConfig(new Tenant()).isEmpty());
        assertTrue(service.resolveRuntimeConfig(null).isEmpty());
    }

    private static Tenant tenant() {
        Tenant tenant = mock(Tenant.class);
        when(tenant.getId()).thenReturn(UUID.randomUUID());
        return tenant;
    }

    private static ServiceNowCmdbConfig config(String baseUrl, String username, String encryptedSecret) {
        ServiceNowCmdbConfig config = new ServiceNowCmdbConfig();
        config.setBaseUrl(baseUrl);
        config.setAuthType(ServiceNowAuthType.BASIC);
        config.setUsername(username);
        config.setCredentialSecret(encryptedSecret);
        return config;
    }
}
