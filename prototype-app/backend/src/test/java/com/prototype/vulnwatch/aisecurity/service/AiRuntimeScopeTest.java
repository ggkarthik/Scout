package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.azure.AzureFoundryRuntimeCollectionService;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioRuntimeCollectionService;
import com.prototype.vulnwatch.aisecurity.controller.AiAgentExecutionController;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AiRuntimeScopeTest {
    private static void gone(Runnable call) {
        var error = assertThrows(ResponseStatusException.class, call::run);
        assertEquals(HttpStatus.GONE, error.getStatusCode());
        assertEquals(AiRuntimeScope.REASON, error.getReason());
    }
    @Test void enabledProviderCollectorsNeverAccessCredentialsOrProviderApis() {
        var foundry = new AzureFoundryRuntimeCollectionService(null,null,null,null,null,null,null,true);
        var copilot = new CopilotStudioRuntimeCollectionService(null,null,null,null,null,null,true,true);
        gone(() -> foundry.run(new Tenant()));
        gone(() -> copilot.run(new Tenant(), UUID.randomUUID()));
    }
    @Test void executionReadEndpointsAreRetiredWithoutReadingHistoricalData() {
        var execution = mock(AiAgentExecutionApiService.class);
        var controller = new AiAgentExecutionController(null,null,execution);
        gone(() -> controller.list(null,null,null,null,null,null,0,50));
        gone(() -> controller.timeline(UUID.randomUUID()));
        gone(() -> controller.relationships(UUID.randomUUID()));
        verifyNoInteractions(execution);
    }
    @Test void sharedExecutionWriteBoundaryRejectsEvenDirectCalls() {
        var service = new AiAgentExecutionIngestionService(null,null,null,null,1000,16384,30,3);
        gone(() -> service.ingest(new Tenant(),null,null));
    }
    @Test void curatedActivityCannotEnterThroughTheGeneralEvidencePort() {
        var service = new AiGridHostContextService(null,new ObjectMapper());
        var input = new AiGridHostContextService.TrustedFactInput("activity.agent_invocation_observed",
                new ObjectMapper().valueToTree(true),"KNOWN",null,null,null,null,1.0);
        gone(() -> service.ingestTrusted(new Tenant(),UUID.randomUUID(),"SCOUT_AWS_ACTIVITY",input));
    }
    @Test void runtimePackagesCannotBeApprovedOrPublishedByPlatformOwners() {
        var governance = new AiGridValidationGovernanceService(null,null,new ObjectMapper(),null,null);
        gone(() -> governance.approvePolicy("AGCF-RT-005","test"));
        gone(() -> governance.deployToDevTenants("AGCF-RT-005",List.of(),"test","test"));
        gone(() -> governance.publishApprovedPolicy("AGCF-RT-005",null,"test"));
    }
    @Test void tenantAndPlatformPolicyActivationCannotOverrideTheReleaseScope() {
        var api = new AiGridApiService(null,null,null,null,null,null,null,null,null,null,null,null,null);
        gone(() -> api.updateSelection(new Tenant(),"AGCF-RT-005","ENABLED","test","test"));
        var catalog = new AiGridPolicyCatalogService(null,new ObjectMapper(),null,null);
        gone(() -> catalog.updateDistribution("AGCF-RT-005",
                new AiGridPolicyCatalogService.DistributionCommand(true,"ENABLED","GENERAL_AVAILABILITY",List.of(),"1.0.0"),"test"));
    }
}
