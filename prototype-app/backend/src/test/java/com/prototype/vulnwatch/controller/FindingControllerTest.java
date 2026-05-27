package com.prototype.vulnwatch.controller;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingBulkWorkflowRequest;
import com.prototype.vulnwatch.dto.FindingBulkWorkflowResponse;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.service.FindingQueryService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class FindingControllerTest {

    @Mock private WorkspaceService workspaceService;
    @Mock private FindingQueryService findingQueryService;
    @Mock private FindingWorkflowService findingWorkflowService;

    private MockMvc mockMvc;
    private Tenant tenant;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    @BeforeEach
    void setUp() {
        FindingController controller = new FindingController(
                workspaceService, findingQueryService, findingWorkflowService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
        tenant = new Tenant();
        tenant.setId(UUID.fromString("00000000-0000-0000-0000-000000000001"));
        tenant.setName("default");
    }

    @Test
    void listReturnsPagedFindings() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(findingQueryService.listByTenantPage(
                eq(tenant), eq(0), eq(25),
                isNull(), isNull(), isNull(), isNull(), isNull(),
                isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull()
        )).thenReturn(new FindingPageResponse(List.of(), 0, 25, 3L, 1));

        mockMvc.perform(get("/api/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(0))
                .andExpect(jsonPath("$.size").value(25))
                .andExpect(jsonPath("$.totalItems").value(3))
                .andExpect(jsonPath("$.totalPages").value(1));
    }

    @Test
    void listPassesFilterParamsToQueryService() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(findingQueryService.listByTenantPage(
                eq(tenant), eq(1), eq(10),
                eq(List.of("CRITICAL")), eq(List.of("OPEN")),
                isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull()
        )).thenReturn(new FindingPageResponse(List.of(), 1, 10, 0L, 0));

        mockMvc.perform(get("/api/findings")
                        .param("page", "1")
                        .param("size", "10")
                        .param("severity", "CRITICAL")
                        .param("status", "OPEN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.page").value(1));

        verify(findingQueryService).listByTenantPage(
                eq(tenant), eq(1), eq(10),
                eq(List.of("CRITICAL")), eq(List.of("OPEN")),
                isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull(), isNull());
    }

    @Test
    void filtersReturnsAvailableFilterValues() throws Exception {
        when(workspaceService.getWorkspace()).thenReturn(tenant);
        when(findingQueryService.listAvailableFilters(tenant)).thenReturn(
                new FindingFilterValuesResponse(
                        List.of("CRITICAL", "HIGH"), List.of("OPEN", "RESOLVED"),
                        List.of("AFFECTED"), List.of("CPE"), List.of(), List.of(), List.of()));

        mockMvc.perform(get("/api/findings/filters"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.severities[0]").value("CRITICAL"))
                .andExpect(jsonPath("$.statuses[0]").value("OPEN"));

        verify(findingQueryService).listAvailableFilters(tenant);
    }

    @Test
    void updateWorkflowDelegatesToWorkflowService() throws Exception {
        UUID findingId = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        Finding updated = new Finding();
        ReflectionTestUtils.setField(updated, "id", findingId);
        updated.setStatus(FindingStatus.RESOLVED);
        when(findingWorkflowService.updateWorkflow(eq(findingId), any())).thenReturn(updated);

        FindingWorkflowUpdateRequest req = new FindingWorkflowUpdateRequest(
                "RESOLVED", null, null, null, null, null, "analyst@example.com");

        mockMvc.perform(put("/api/findings/{id}/workflow", findingId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("RESOLVED"));

        verify(findingWorkflowService).updateWorkflow(eq(findingId), any());
    }

    @Test
    void bulkWorkflowWithEmptyListReturnsZeroCountsWithoutCallingService() throws Exception {
        FindingBulkWorkflowRequest req = new FindingBulkWorkflowRequest(
                List.of(), null, null, null, null, null, null, null, null,
                null, null, null, null, "ACKNOWLEDGED", null, null, null, null, null);

        mockMvc.perform(post("/api/findings/bulk-workflow")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targeted").value(0))
                .andExpect(jsonPath("$.updated").value(0));
    }

    @Test
    void bulkWorkflowWithFindingIdsDelegatesToWorkflowService() throws Exception {
        UUID id1 = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
        UUID id2 = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");
        when(findingWorkflowService.updateWorkflowBulkByIds(eq(List.of(id1, id2)), any())).thenReturn(2);

        FindingBulkWorkflowRequest req = new FindingBulkWorkflowRequest(
                List.of(id1, id2), null, null, null, null, null, null, null, null,
                null, null, null, null, "RESOLVED", null, null, null, null, null);

        mockMvc.perform(post("/api/findings/bulk-workflow")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.targeted").value(2))
                .andExpect(jsonPath("$.updated").value(2))
                .andExpect(jsonPath("$.failed").value(0));
    }

    @Test
    void bulkDeleteWithEmptyListReturnsZeroDeleted() throws Exception {
        FindingController.BulkDeleteRequest req = new FindingController.BulkDeleteRequest(List.of());

        mockMvc.perform(delete("/api/findings/bulk")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deleted").value(0));
    }

    @Test
    void bulkDeleteWithFindingIdsDelegatesToWorkflowService() throws Exception {
        UUID id1 = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");
        when(findingWorkflowService.bulkDelete(List.of(id1))).thenReturn(1);

        FindingController.BulkDeleteRequest req = new FindingController.BulkDeleteRequest(List.of(id1));

        mockMvc.perform(delete("/api/findings/bulk")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(req)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.deleted").value(1));

        verify(findingWorkflowService).bulkDelete(List.of(id1));
    }
}
