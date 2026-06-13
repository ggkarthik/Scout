package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.CampaignStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignCreateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignExceptionStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNoteResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignNotifyGroupRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignStatusUpdateRequest;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignSummaryResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignWatchlistEntryUpdateRequest;
import com.prototype.vulnwatch.service.CampaignService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/campaigns")
public class CampaignController {

    private final WorkspaceService workspaceService;
    private final RequestActorService requestActorService;
    private final CampaignService campaignService;

    public CampaignController(
            WorkspaceService workspaceService,
            RequestActorService requestActorService,
            CampaignService campaignService
    ) {
        this.workspaceService = workspaceService;
        this.requestActorService = requestActorService;
        this.campaignService = campaignService;
    }

    @GetMapping
    public List<CampaignSummaryResponse> list(@RequestParam(required = false) CampaignStatus status) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.list(tenant, status);
    }

    @GetMapping("/{campaignId}")
    public CampaignDetailResponse detail(@PathVariable UUID campaignId) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.getDetail(tenant, campaignId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse create(@RequestBody CampaignCreateRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.create(tenant, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/status")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateStatus(
            @PathVariable UUID campaignId,
            @RequestBody CampaignStatusUpdateRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateStatus(tenant, campaignId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/notes")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignNoteResponse addNote(
            @PathVariable UUID campaignId,
            @RequestBody CampaignNoteRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.addNote(tenant, campaignId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/exceptions")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignExceptionResponse addException(
            @PathVariable UUID campaignId,
            @RequestBody CampaignExceptionRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.addException(tenant, campaignId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/notify-groups/{notifyGroupId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateNotifyGroup(
            @PathVariable UUID campaignId,
            @PathVariable UUID notifyGroupId,
            @RequestBody CampaignNotifyGroupRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateNotifyGroup(tenant, campaignId, notifyGroupId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/watchlist/{watchlistEntryId}")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateWatchlistEntry(
            @PathVariable UUID campaignId,
            @PathVariable UUID watchlistEntryId,
            @RequestBody CampaignWatchlistEntryUpdateRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateWatchlistEntry(tenant, campaignId, watchlistEntryId, request, requestActorService.currentActor().userId());
    }

    @PostMapping("/{campaignId}/exceptions/{exceptionId}/status")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public CampaignDetailResponse updateExceptionStatus(
            @PathVariable UUID campaignId,
            @PathVariable UUID exceptionId,
            @RequestBody CampaignExceptionStatusUpdateRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return campaignService.updateExceptionStatus(tenant, campaignId, exceptionId, request, requestActorService.currentActor().userId());
    }
}
