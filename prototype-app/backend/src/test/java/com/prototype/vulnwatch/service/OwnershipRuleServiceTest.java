package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.OwnershipRule;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.OwnershipRuleRequest;
import com.prototype.vulnwatch.dto.OwnershipRuleResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.OwnershipRuleRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class OwnershipRuleServiceTest {

    @Mock private OwnershipRuleRepository repository;
    @Mock private FindingRepository findingRepository;
    @Mock private FindingsScoreService findingsScoreService;
    @Mock private TenantSchemaExecutionService tenantSchemaExecutionService;

    private OwnershipRuleService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        lenient().doAnswer(inv -> inv.getArgument(1, Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(nullable(Tenant.class), any(Supplier.class));
        service = new OwnershipRuleService(
                repository,
                findingRepository,
                findingsScoreService,
                new ObjectMapper(),
                tenantSchemaExecutionService
        );
    }

    private Tenant tenant() {
        Tenant t = new Tenant();
        t.setId(UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"));
        t.setName("Acme");
        t.setSchemaName("tenant_acme");
        return t;
    }

    private OwnershipRule rule(Tenant tenant, String name, String userGroup) {
        OwnershipRule r = new OwnershipRule();
        r.setTenant(tenant);
        r.setName(name);
        r.setUserGroup(userGroup);
        r.setConditionJson("{\"logic\":\"AND\",\"conditions\":[]}");
        return r;
    }

    @Test
    void list_returnsEmptyWhenNoRulesExist() {
        Tenant tenant = tenant();
        when(repository.findAllByOrderByExecutionOrderAscCreatedAtAsc()).thenReturn(List.of());

        List<OwnershipRuleResponse> result = service.list(tenant);

        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    void list_returnsRulesForTenant() {
        Tenant tenant = tenant();
        OwnershipRule r = rule(tenant, "Security Team", "security-team");
        when(repository.findAllByOrderByExecutionOrderAscCreatedAtAsc()).thenReturn(List.of(r));
        when(findingRepository.countByOwnerGroup("security-team")).thenReturn(5L);

        List<OwnershipRuleResponse> result = service.list(tenant);

        assertEquals(1, result.size());
        assertEquals("Security Team", result.get(0).name());
        assertEquals("security-team", result.get(0).userGroup());
        assertEquals(5L, result.get(0).matchedCount());
    }

    @Test
    void create_savesRuleAndReturnsResponse() {
        Tenant tenant = tenant();
        OwnershipRule saved = rule(tenant, "Ops Team", "ops");
        when(repository.save(any(OwnershipRule.class))).thenReturn(saved);
        when(findingRepository.countByOwnerGroup("ops")).thenReturn(0L);

        OwnershipRuleRequest req = new OwnershipRuleRequest("Ops Team", "{}", "ops", 1);

        OwnershipRuleResponse response = service.create(tenant, req);

        assertNotNull(response);
        assertEquals("Ops Team", response.name());
        assertEquals("ops", response.userGroup());
        verify(repository).save(any(OwnershipRule.class));
    }

    @Test
    void create_throwsBadRequestWhenNameIsBlank() {
        Tenant tenant = tenant();
        OwnershipRuleRequest req = new OwnershipRuleRequest("", "{}", "ops", 1);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.create(tenant, req));

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
        verify(repository, never()).save(any());
    }

    @Test
    void create_throwsBadRequestWhenUserGroupIsBlank() {
        Tenant tenant = tenant();
        OwnershipRuleRequest req = new OwnershipRuleRequest("Ops Team", "{}", "  ", 1);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.create(tenant, req));

        assertEquals(HttpStatus.BAD_REQUEST, ex.getStatusCode());
        verify(repository, never()).save(any());
    }

    @Test
    void update_throwsNotFoundWhenRuleDoesNotExist() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");
        when(repository.findById(ruleId)).thenReturn(Optional.empty());

        OwnershipRuleRequest req = new OwnershipRuleRequest("Ops Team", "{}", "ops", 1);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.update(ruleId, tenant, req));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }

    @Test
    void update_throwsNotFoundWhenRuleBelongsToDifferentTenant() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");

        Tenant otherTenant = new Tenant();
        otherTenant.setId(UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        OwnershipRule r = rule(otherTenant, "Foreign Rule", "foreign-group");

        when(repository.findById(ruleId)).thenReturn(Optional.of(r));

        OwnershipRuleRequest req = new OwnershipRuleRequest("Ops Team", "{}", "ops", 1);

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.update(ruleId, tenant, req));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
    }

    @Test
    void delete_removesRuleFromRepository() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");
        OwnershipRule r = rule(tenant, "Delete Me", "delete-group");

        when(repository.findById(ruleId)).thenReturn(Optional.of(r));

        service.delete(ruleId, tenant);

        verify(repository).delete(r);
    }

    @Test
    void delete_throwsNotFoundWhenRuleDoesNotExist() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("ffffffff-0000-0000-0000-000000000000");
        when(repository.findById(ruleId)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.delete(ruleId, tenant));

        assertEquals(HttpStatus.NOT_FOUND, ex.getStatusCode());
        verify(repository, never()).delete(any());
    }
}
