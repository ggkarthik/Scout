package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class IngestionJobLockServiceTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Test
    void assetLockKeyIsStableAndNormalizesAssetIdentifier() {
        IngestionJobLockService service = new IngestionJobLockService(jdbcTemplate);
        UUID tenantId = UUID.randomUUID();

        long first = service.assetLockKey(tenantId, " Registry.EXAMPLE.com/Payments ");
        long second = service.assetLockKey(tenantId, "registry.example.com/payments");
        long different = service.assetLockKey(tenantId, "registry.example.com/orders");

        assertEquals(first, second);
        assertNotEquals(first, different);
    }

    @Test
    void tryAcquireTransactionLockUsesPostgresAdvisoryLock() {
        IngestionJobLockService service = new IngestionJobLockService(jdbcTemplate);
        when(jdbcTemplate.queryForObject("select pg_try_advisory_xact_lock(?)", Boolean.class, 42L)).thenReturn(Boolean.TRUE);

        boolean acquired = service.tryAcquireTransactionLock(42L);

        assertTrue(acquired);
        verify(jdbcTemplate).queryForObject("select pg_try_advisory_xact_lock(?)", Boolean.class, 42L);
    }
}
