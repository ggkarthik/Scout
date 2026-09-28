package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowIncidentService;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * {@link TicketingProvider} over the existing ServiceNow incident integration.
 *
 * <p>A thin adapter on purpose: the payload construction, retry policy and error mapping stay
 * in {@link ServiceNowIncidentService}, which is already in production use. This class only
 * translates between the neutral framework types and the ServiceNow-shaped ones.
 */
@Component
public class ServiceNowTicketingProvider implements TicketingProvider {

    private final ServiceNowIncidentService serviceNowIncidentService;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;

    public ServiceNowTicketingProvider(
            ServiceNowIncidentService serviceNowIncidentService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService
    ) {
        this.serviceNowIncidentService = serviceNowIncidentService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
    }

    @Override
    public TicketingSystem system() {
        return TicketingSystem.SERVICENOW;
    }

    /**
     * Presence of a connector config, which is exactly what the pre-existing incident path
     * required. The connector's {@code enabled} flag governs CMDB sync rather than ticketing,
     * so it is deliberately not consulted here — doing so would silently stop incident
     * creation for tenants who only ever disabled inventory sync.
     */
    @Override
    public boolean isConfigured(Tenant tenant) {
        return serviceNowCmdbConfigService.resolveRuntimeConfig(tenant).isPresent();
    }

    @Override
    public TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config =
                serviceNowIncidentService.resolveIncidentConfig(tenant);
        ServiceNowIncidentResponse response = serviceNowIncidentService.createFindingIncidentRemote(
                config, finding, toServiceNowRequest(request));
        return new TicketRef(
                TicketingSystem.SERVICENOW,
                response.incidentNumber(),
                response.sysId(),
                response.url(),
                "New",
                response.message()
        );
    }

    @Override
    public Optional<String> fetchStatus(Tenant tenant, String externalKey) {
        return serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                .map(config -> serviceNowIncidentService.getIncidentStatus(config, externalKey));
    }

    private CreateServiceNowIncidentRequest toServiceNowRequest(TicketRequest request) {
        TicketRequest safe = request == null ? TicketRequest.empty() : request;
        return new CreateServiceNowIncidentRequest(
                safe.title(),
                safe.severity(),
                null,
                null,
                false,
                safe.priority(),
                safe.dueDate(),
                safe.assignee(),
                safe.notes(),
                safe.solutionInfo(),
                safe.dueDate(),
                List.of()
        );
    }
}
