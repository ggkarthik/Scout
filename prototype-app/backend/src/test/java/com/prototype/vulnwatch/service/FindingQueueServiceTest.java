package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.PersonalFindingQueue;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingQueueUpsertRequest;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.dto.FindingSummaryResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.FindingQueuePreferenceRepository;
import com.prototype.vulnwatch.repo.PersonalFindingQueueRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingQueueServiceTest {

    @Mock private FindingAnalyticsService findingAnalyticsService;
    @Mock private PersonalFindingQueueRepository personalFindingQueueRepository;
    @Mock private FindingQueuePreferenceRepository findingQueuePreferenceRepository;
    @Mock private AppUserRepository appUserRepository;
    @Mock private RequestActorService requestActorService;
    @Mock private WorkspaceService workspaceService;

    private FindingQueueService findingQueueService;
    private Tenant tenant;
    private AppUser user;

    @BeforeEach
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        tenant.setName("default");
        user = new AppUser();
        user.setId(UUID.fromString("00000000-0000-0000-0000-000000000010"));
        user.setExternalSubject("alex@example.com");
        user.setDisplayName("Alex");
        FindingQueueDefinitionService definitionService = new FindingQueueDefinitionService(findingAnalyticsService);
        PersonalFindingQueueService personalFindingQueueService = new PersonalFindingQueueService(
                findingAnalyticsService,
                personalFindingQueueRepository,
                findingQueuePreferenceRepository,
                appUserRepository,
                requestActorService,
                new ObjectMapper()
        );
        FindingQueueResolutionService resolutionService = new FindingQueueResolutionService(
                workspaceService,
                definitionService,
                personalFindingQueueService
        );
        findingQueueService = new FindingQueueService(
                definitionService,
                personalFindingQueueService,
                resolutionService
        );
    }

    @Test
    void listQueuesReturnsBuiltInsAndPersonal() throws Exception {
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "alex@example.com",
                false,
                tenant.getId(),
                tenant.getName(),
                Set.of("TENANT_ADMIN")
        ));
        when(appUserRepository.findByExternalSubject("alex@example.com")).thenReturn(Optional.of(user));
        when(findingAnalyticsService.getSummary(eq(tenant), any()))
                .thenReturn(new FindingSummaryResponse(10, 2, 3, 4, 1, 0));
        PersonalFindingQueue personal = new PersonalFindingQueue();
        personal.setId(UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        personal.setTenant(tenant);
        personal.setOwnerUser(user);
        personal.setQueueKey("my-critical");
        personal.setTitle("My Critical");
        personal.setFilterJson(new ObjectMapper().writeValueAsString(new FindingsFilter(
                List.of("CRITICAL"), List.of("OPEN"), null, null, null, null, null, null,
                null, null, null, null, null, "alex@example.com", null, null, null, null, null, null, null
        )));
        when(personalFindingQueueRepository.findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), user.getId()))
                .thenReturn(List.of(personal));

        assertEquals(List.of(
                        "all-findings",
                        "critical-open",
                        "overdue",
                        "unassigned-open",
                        "with-incidents",
                        "incident-needed",
                        "patch-available",
                        "sla-breach-risk",
                        "unassigned-critical",
                        "deferred-expiring-soon",
                        "personal:aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"),
                findingQueueService.listQueues(tenant).stream().map(queue -> queue.key()).toList());
    }

    @Test
    void createQueuePersistsPersonalQueue() {
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "alex@example.com",
                false,
                tenant.getId(),
                tenant.getName(),
                Set.of("TENANT_ADMIN")
        ));
        when(appUserRepository.findByExternalSubject("alex@example.com")).thenReturn(Optional.of(user));
        when(personalFindingQueueRepository.findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), user.getId()))
                .thenReturn(List.of());
        when(personalFindingQueueRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));
        when(findingAnalyticsService.getSummary(eq(tenant), any()))
                .thenReturn(new FindingSummaryResponse(4, 1, 0, 0, 0, 0));

        findingQueueService.createQueue(tenant, new FindingQueueUpsertRequest(
                "My Queue",
                "Saved view",
                new FindingsFilter(List.of("CRITICAL"), List.of("OPEN"), null, null, null, null, null, null,
                        null, null, null, null, null, null, null, null, null, null, null, null, null),
                null,
                "critical-open",
                false
        ));

        ArgumentCaptor<PersonalFindingQueue> captor = ArgumentCaptor.forClass(PersonalFindingQueue.class);
        verify(personalFindingQueueRepository).save(captor.capture());
        assertEquals("my-queue", captor.getValue().getQueueKey());
        assertEquals("My Queue", captor.getValue().getTitle());
    }

    @Test
    void resolveEffectiveFilterMergesNarrowingFilters() {
        FindingsFilter effective = findingQueueService.resolveEffectiveFilter(
                "critical-open",
                new FindingsFilter(List.of("CRITICAL"), null, null, null, null, null, null, null,
                        null, null, null, null, null, "alex@example.com", null, null, null, null, null, null, null)
        );

        assertEquals(List.of("CRITICAL"), effective.severity());
        assertEquals(List.of("OPEN"), effective.status());
        assertEquals("alex@example.com", effective.assignedTo());
    }

    @Test
    void resolveEffectiveFilterRejectsBroadeningStatus() {
        IllegalArgumentException error = assertThrows(IllegalArgumentException.class, () -> findingQueueService.resolveEffectiveFilter(
                "critical-open",
                new FindingsFilter(null, List.of("RESOLVED"), null, null, null, null, null, null,
                        null, null, null, null, null, null, null, null, null, null, null, null, null)
        ));

        assertEquals("Filter conflicts with queue \"Critical Open\" for field: status", error.getMessage());
    }

    @Test
    void settingBuiltInDefaultLeavesNoPersonalQueueMarkedDefault() throws Exception {
        when(requestActorService.currentActor()).thenReturn(new RequestActor(
                "alex@example.com",
                false,
                tenant.getId(),
                tenant.getName(),
                Set.of("TENANT_ADMIN")
        ));
        when(appUserRepository.findByExternalSubject("alex@example.com")).thenReturn(Optional.of(user));
        PersonalFindingQueue personal = new PersonalFindingQueue();
        personal.setId(UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        personal.setTenant(tenant);
        personal.setOwnerUser(user);
        personal.setQueueKey("my-overdue");
        personal.setTitle("My Overdue");
        personal.setDefault(true);
        personal.setFilterJson(new ObjectMapper().writeValueAsString(new FindingsFilter(
                null, List.of("OPEN"), null, null, null, null, null, null,
                null, null, null, null, null, null, null, null, "overdue", null, null, null, null
        )));
        when(personalFindingQueueRepository.findByTenantIdAndOwnerUserIdOrderByDisplayOrderAscCreatedAtAsc(tenant.getId(), user.getId()))
                .thenReturn(List.of(personal));
        when(personalFindingQueueRepository.save(any())).thenAnswer(invocation -> invocation.getArgument(0));

        findingQueueService.setDefaultQueue(tenant, "overdue");

        assertFalse(personal.isDefault());
    }
}
