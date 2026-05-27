package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.RiskPolicyRequest;
import com.prototype.vulnwatch.dto.RiskPolicyResponse;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

@ExtendWith(MockitoExtension.class)
class RiskPolicyServiceTest {

    @Mock private RiskPolicyRepository riskPolicyRepository;
    @Mock private InventoryComponentRepository inventoryComponentRepository;
    @Mock private ObjectProvider<FindingDeltaQueueService> findingDeltaQueueServiceProvider;
    @Mock private TenantSchemaExecutionService tenantSchemaExecutionService;

    private RiskPolicyService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        lenient().doAnswer(inv -> inv.getArgument(1, Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(nullable(Tenant.class), any(Supplier.class));
        service = new RiskPolicyService(
                riskPolicyRepository,
                inventoryComponentRepository,
                findingDeltaQueueServiceProvider,
                tenantSchemaExecutionService
        );
    }

    private Tenant tenant() {
        Tenant t = new Tenant();
        t.setId(UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        t.setName("Acme");
        t.setSchemaName("tenant_acme");
        return t;
    }

    @Test
    void getOrCreate_returnsExistingPolicyWhenFound() {
        Tenant tenant = tenant();
        RiskPolicy existing = new RiskPolicy();
        existing.setTenant(tenant);
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.of(existing));

        RiskPolicy result = service.getOrCreate(tenant);

        assertNotNull(result);
        verify(riskPolicyRepository).findTopByOrderByUpdatedAtDesc();
        verify(riskPolicyRepository, never()).save(any());
    }

    @Test
    void getOrCreate_createsNewPolicyWhenNoneExists() {
        Tenant tenant = tenant();
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.empty());
        RiskPolicy saved = new RiskPolicy();
        saved.setTenant(tenant);
        when(riskPolicyRepository.save(any(RiskPolicy.class))).thenReturn(saved);

        RiskPolicy result = service.getOrCreate(tenant);

        assertNotNull(result);
        verify(riskPolicyRepository).save(any(RiskPolicy.class));
    }

    @Test
    void update_appliesCriticalSlaDaysAndSaves() {
        Tenant tenant = tenant();
        RiskPolicy existing = new RiskPolicy();
        existing.setTenant(tenant);
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.of(existing));
        when(riskPolicyRepository.save(existing)).thenReturn(existing);

        RiskPolicyRequest req = new RiskPolicyRequest(
                null, null, 3, null, null, null,
                null, null, null, null,
                null, null, null, null, null
        );

        RiskPolicyResponse response = service.update(tenant, req);

        assertNotNull(response);
        assertEquals(3, existing.getCriticalSlaDays());
        verify(riskPolicyRepository).save(existing);
    }

    @Test
    void update_clampsNegativeSlaDaysToZero() {
        Tenant tenant = tenant();
        RiskPolicy existing = new RiskPolicy();
        existing.setTenant(tenant);
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.of(existing));
        when(riskPolicyRepository.save(existing)).thenReturn(existing);

        RiskPolicyRequest req = new RiskPolicyRequest(
                null, null, -5, null, null, null,
                null, null, null, null,
                null, null, null, null, null
        );

        service.update(tenant, req);

        assertEquals(0, existing.getCriticalSlaDays());
    }

    @Test
    void update_ignoresNullFields() {
        Tenant tenant = tenant();
        RiskPolicy existing = new RiskPolicy();
        existing.setTenant(tenant);
        existing.setCriticalSlaDays(7);
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.of(existing));
        when(riskPolicyRepository.save(existing)).thenReturn(existing);

        RiskPolicyRequest req = new RiskPolicyRequest(
                null, null, null, null, null, null,
                null, null, null, null,
                null, null, null, null, null
        );

        service.update(tenant, req);

        assertEquals(7, existing.getCriticalSlaDays());
    }

    @Test
    void get_delegatesToGetOrCreateAndMapsResponse() {
        Tenant tenant = tenant();
        RiskPolicy existing = new RiskPolicy();
        existing.setTenant(tenant);
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.of(existing));

        RiskPolicyResponse response = service.get(tenant);

        assertNotNull(response);
        verify(riskPolicyRepository).findTopByOrderByUpdatedAtDesc();
    }

    @Test
    void getFindingsScoreConfig_returnsEmptyArrayWhenNoPolicyExists() {
        Tenant tenant = tenant();
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.empty());

        String config = service.getFindingsScoreConfig(tenant);

        assertEquals("[]", config);
    }

    @Test
    void getFindingsScoreConfig_returnsPolicyConfigWhenExists() {
        Tenant tenant = tenant();
        RiskPolicy existing = new RiskPolicy();
        existing.setTenant(tenant);
        when(riskPolicyRepository.findTopByOrderByUpdatedAtDesc()).thenReturn(Optional.of(existing));

        String config = service.getFindingsScoreConfig(tenant);

        assertEquals("[]", config);
    }
}
