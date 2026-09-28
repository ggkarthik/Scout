package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

/** Unit-level coverage of the daily admission decision, without a database. */
@ExtendWith(MockitoExtension.class)
class AiBomProjectionBudgetServiceTest {

    @Mock private NamedParameterJdbcTemplate jdbc;
    @Mock private TenantSchemaExecutionService tenantExecution;
    @Mock private TransactionTemplate transactions;

    private Tenant tenant;

    @BeforeEach
    void setUp() {
        lenient().when(tenantExecution.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        lenient().when(transactions.execute(any()))
                .thenAnswer(invocation -> ((TransactionCallback<?>) invocation.getArgument(0)).doInTransaction(null));
        lenient().when(jdbc.queryForObject(anyString(), anyMap(), eq(String.class))).thenReturn("t");

        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
    }

    @Test
    void underTheLimitIsAdmittedAndIncrementsTheAdmittedCounter() {
        when(jdbc.queryForObject(anyString(), anyMap(), eq(Integer.class))).thenReturn(0);
        AiBomProjectionBudgetService service =
                new AiBomProjectionBudgetService(jdbc, tenantExecution, transactions, 100);

        AiBomProjectionBudgetService.Decision decision = service.admit(tenant);

        assertEquals(AiBomProjectionBudgetService.Decision.ADMITTED, decision);
        var sqlCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(jdbc, org.mockito.Mockito.atLeastOnce()).update(sqlCaptor.capture(), any(org.springframework.jdbc.core.namedparam.MapSqlParameterSource.class));
        assertTrue(sqlCaptor.getAllValues().stream().anyMatch(sql -> sql.contains("admitted_count = admitted_count + 1")),
                "an admission must increment admitted_count, not throttled_count");
    }

    @Test
    void atTheLimitIsThrottled() {
        when(jdbc.queryForObject(anyString(), anyMap(), eq(Integer.class))).thenReturn(1);
        AiBomProjectionBudgetService service =
                new AiBomProjectionBudgetService(jdbc, tenantExecution, transactions, 1);

        AiBomProjectionBudgetService.Decision decision = service.admit(tenant);

        assertEquals(AiBomProjectionBudgetService.Decision.THROTTLED, decision);
        var sqlCaptor = org.mockito.ArgumentCaptor.forClass(String.class);
        verify(jdbc, org.mockito.Mockito.atLeastOnce()).update(sqlCaptor.capture(), any(org.springframework.jdbc.core.namedparam.MapSqlParameterSource.class));
        assertTrue(sqlCaptor.getAllValues().stream().anyMatch(sql -> sql.contains("throttled_count = throttled_count + 1")),
                "a throttle must increment throttled_count, not admitted_count");
    }

    @Test
    void zeroIsUnderAOneAdmissionLimit() {
        when(jdbc.queryForObject(anyString(), anyMap(), eq(Integer.class))).thenReturn(0);
        AiBomProjectionBudgetService service =
                new AiBomProjectionBudgetService(jdbc, tenantExecution, transactions, 1);

        assertEquals(AiBomProjectionBudgetService.Decision.ADMITTED, service.admit(tenant));
    }
}
