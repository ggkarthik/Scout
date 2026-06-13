package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OperationalDemoPurgeDryRunCandidateResponse;
import com.prototype.vulnwatch.dto.OperationalDemoPurgeDryRunResponse;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DemoTenantPurgePlannerTest {

    @Mock
    private TenantRepository tenantRepository;

    @Test
    void buildSnapshotIncludesEligibleAndFlaggedDemoTenants() {
        Instant now = Instant.parse("2026-06-12T02:30:00Z");
        Tenant ready = demoTenant("Ready", "ACTIVE", null, null, Instant.parse("2026-06-11T00:00:00Z"));
        Tenant retry = demoTenant("Retry", "EXPIRED", "FAILED", null, Instant.parse("2026-06-10T00:00:00Z"));
        Tenant purging = demoTenant("Purging", "PURGING", "IN_PROGRESS", null, Instant.parse("2026-06-10T00:00:00Z"));
        Tenant purged = demoTenant("Purged", "DELETED", "COMPLETED", Instant.parse("2026-06-11T03:00:00Z"), Instant.parse("2026-06-09T00:00:00Z"));
        Tenant future = demoTenant("Future", "ACTIVE", null, null, Instant.parse("2026-06-20T00:00:00Z"));

        when(tenantRepository.findAllByOrderByCreatedAtAsc()).thenReturn(List.of(ready, retry, purging, purged, future));

        DemoTenantPurgePlanner planner = new DemoTenantPurgePlanner(tenantRepository, new TenantLifecycleGuardService());
        OperationalDemoPurgeDryRunResponse snapshot = planner.buildSnapshot(now);

        assertEquals(2, snapshot.totalCandidates());
        assertEquals(4, snapshot.candidates().size());
        assertNotNull(snapshot.candidates().stream().filter(candidate -> "EXPIRED_READY".equals(candidate.eligibilityReason())).findFirst().orElse(null));
        assertNotNull(snapshot.candidates().stream().filter(candidate -> "PURGE_RETRY_REQUIRED".equals(candidate.eligibilityReason())).findFirst().orElse(null));
        assertNotNull(snapshot.candidates().stream().filter(candidate -> "PURGE_IN_PROGRESS".equals(candidate.eligibilityReason())).findFirst().orElse(null));
        assertNotNull(snapshot.candidates().stream().filter(candidate -> "ALREADY_PURGED".equals(candidate.eligibilityReason())).findFirst().orElse(null));
        assertEquals(2, snapshot.candidates().stream().filter(OperationalDemoPurgeDryRunCandidateResponse::eligible).count());
    }

    @Test
    void automaticPurgeEligibilityMatchesNonDestructivePlanLogic() {
        Instant now = Instant.parse("2026-06-12T02:30:00Z");
        DemoTenantPurgePlanner planner = new DemoTenantPurgePlanner(tenantRepository, new TenantLifecycleGuardService());

        assertTrue(planner.isEligibleForAutomaticPurge(
                demoTenant("Expired", "EXPIRED", null, null, Instant.parse("2026-06-11T00:00:00Z")),
                now
        ));
        assertTrue(planner.isEligibleForAutomaticPurge(
                demoTenant("Retry", "ACTIVE", "FAILED", null, Instant.parse("2026-06-11T00:00:00Z")),
                now
        ));
    }

    private Tenant demoTenant(String name, String status, String purgeStatus, Instant purgedAt, Instant demoExpiresAt) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setSchemaName("tenant_" + name.toLowerCase());
        tenant.setPlanCode(DemoLifecycleService.DEMO_PLAN_CODE);
        tenant.setStatus(status);
        tenant.setPurgeStatus(purgeStatus);
        tenant.setPurgedAt(purgedAt);
        tenant.setDemoExpiresAt(demoExpiresAt);
        return tenant;
    }
}
