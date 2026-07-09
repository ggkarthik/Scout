package com.prototype.vulnwatch.service;

import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;

@ExtendWith(MockitoExtension.class)
class FindingProjectionQueryServiceTest {

    @Mock
    private NamedParameterJdbcTemplate jdbcTemplate;

    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Mock
    private FindingProjectionStatusService findingProjectionStatusService;

    @Mock
    private FindingProjectionRefreshService findingProjectionRefreshService;

    @Mock
    private PlatformTransactionManager transactionManager;

    private FindingProjectionQueryService service;

    @BeforeEach
    void setUp() {
        service = new FindingProjectionQueryService(
                jdbcTemplate,
                tenantSchemaExecutionService,
                findingProjectionStatusService,
                findingProjectionRefreshService,
                transactionManager
        );
    }

    @Test
    void ensureTenantProjectionRefreshesWhenProjectionIsStale() {
        Tenant tenant = tenant("stale");
        when(findingProjectionStatusService.inspectProjectionStatus(tenant))
                .thenReturn(new FindingListProjectionService.ProjectionStatus(
                        Instant.now().minusSeconds(3600),
                        12,
                        12,
                        40L,
                        true,
                        0L
                ));

        service.ensureTenantProjection(tenant);

        verify(findingProjectionRefreshService).refreshTenant(tenant);
    }

    @Test
    void ensureTenantProjectionSkipsRefreshWhenProjectionIsFresh() {
        Tenant tenant = tenant("fresh");
        when(findingProjectionStatusService.inspectProjectionStatus(tenant))
                .thenReturn(new FindingListProjectionService.ProjectionStatus(
                        Instant.now(),
                        12,
                        12,
                        40L,
                        false,
                        0L
                ));

        service.ensureTenantProjection(tenant);

        verify(findingProjectionRefreshService, never()).refreshTenant(tenant);
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setSchemaName("tenant_" + name);
        return tenant;
    }
}
