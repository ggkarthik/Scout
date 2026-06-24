package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.SimpleTransactionStatus;

class TenantWorkRunnerTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void forEachActiveTenantContinuesAfterPerTenantFailure() {
        TenantService tenantService = mock(TenantService.class);
        TenantSchemaExecutionService executionService = mock(TenantSchemaExecutionService.class);
        PlatformTransactionManager transactionManager = transactionManager();
        Tenant broken = tenant("tenant_broken");
        Tenant healthy = tenant("tenant_healthy");
        when(tenantService.listActiveTenants()).thenReturn(List.of(broken, healthy));
        doAnswer(invocation -> {
            Tenant tenant = invocation.getArgument(0);
            java.util.function.Supplier<?> supplier = invocation.getArgument(1);
            if (tenant == broken) {
                throw new IllegalStateException("boom");
            }
            return supplier.get();
        }).when(executionService).run(any(Tenant.class), any(java.util.function.Supplier.class));

        TenantWorkRunner runner = new TenantWorkRunner(tenantService, executionService, transactionManager);
        List<UUID> visited = new ArrayList<>();

        runner.forEachActiveTenant(tenant -> visited.add(tenant.getId()));

        assertThat(visited).containsExactly(healthy.getId());
    }

    @Test
    void runScopedEntersTenantContextBeforeOpeningTransaction() {
        TenantService tenantService = mock(TenantService.class);
        TenantSchemaExecutionService executionService = mock(TenantSchemaExecutionService.class);
        PlatformTransactionManager transactionManager = transactionManager();
        Tenant tenant = tenant("tenant_acme");
        doAnswer(invocation -> {
            java.util.function.Supplier<?> supplier = invocation.getArgument(1);
            TenantContext.setCurrentTenantId(tenant.getId());
            TenantContext.setCurrentSchemaName(tenant.getSchemaName());
            return supplier.get();
        }).when(executionService).run(any(Tenant.class), any(java.util.function.Supplier.class));

        TenantWorkRunner runner = new TenantWorkRunner(tenantService, executionService, transactionManager);

        String schemaInsideWork = runner.runScoped(tenant, TenantContext::getCurrentSchemaName);

        assertThat(schemaInsideWork).isEqualTo("tenant_acme");
    }

    private PlatformTransactionManager transactionManager() {
        return new PlatformTransactionManager() {
            @Override
            public TransactionStatus getTransaction(TransactionDefinition definition) {
                return new SimpleTransactionStatus();
            }

            @Override
            public void commit(TransactionStatus status) {
            }

            @Override
            public void rollback(TransactionStatus status) {
            }
        };
    }

    private Tenant tenant(String schemaName) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(schemaName);
        tenant.setSlug(schemaName);
        tenant.setSchemaName(schemaName);
        tenant.setStatus("ACTIVE");
        return tenant;
    }
}
