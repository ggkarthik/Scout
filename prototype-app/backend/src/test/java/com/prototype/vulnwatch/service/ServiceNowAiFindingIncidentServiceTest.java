package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

class ServiceNowAiFindingIncidentServiceTest {

    @Test
    void createsAndLinksIncidentForCanonicalAiFinding() throws Exception {
        ServiceNowCmdbConfigService configs = mock(ServiceNowCmdbConfigService.class);
        OutboundHttpClient outbound = mock(OutboundHttpClient.class);
        FindingRepository findings = mock(FindingRepository.class);
        Tenant tenant = mock(Tenant.class);
        UUID findingId = UUID.randomUUID();
        Finding finding = mock(Finding.class);
        when(finding.getStatus()).thenReturn(FindingStatus.OPEN);
        when(finding.getDisplayId()).thenReturn("F-AI000000001");
        when(finding.getTitle()).thenReturn("Weak attached guardrail");
        when(finding.getSeverityOverride()).thenReturn("HIGH");
        when(finding.getRiskScore()).thenReturn(8.0);
        when(finding.getOwnerGroup()).thenReturn("AI Platform Team");
        when(finding.getPolicyId()).thenReturn("AWS_BEDROCK_WEAK_GUARDRAIL");
        when(finding.getReasonCode()).thenReturn("BEDROCK_GUARDRAIL_BELOW_APPROVED_STRENGTH");
        when(findings.findById(findingId)).thenReturn(Optional.of(finding));
        when(configs.resolveRuntimeConfig(tenant)).thenReturn(Optional.of(new ServiceNowCmdbConfigService.ServiceNowRuntimeConfig(
                "https://example.service-now.com", ServiceNowAuthType.BASIC, "scout", "secret",
                "cmdb_sam_sw_install", "cmdb_software_product_model", "cmdb_ci", "", "", "", "",
                100, true, false, 60)));
        when(outbound.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any())).thenReturn(ResponseEntity.ok(
                "{\"result\":{\"number\":\"INC0012345\",\"sys_id\":\"abc123\"}}"));
        ServiceNowIncidentService service = new ServiceNowIncidentService(configs, outbound,
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 1, 0, 0, true, true)),
                new ObjectMapper(), findings);

        var result = service.createFindingIncident(tenant, findingId,
                new CreateServiceNowIncidentRequest(null, null, null, null, false, null,
                        null, null, "Escalate governed AI posture finding", "Raise guardrail strength",
                        null, java.util.List.of()));

        assertEquals("INC0012345", result.incidentNumber());
        verify(finding).setIncidentId("INC0012345");
        verify(finding).setIncidentStatus("New");
        verify(findings).save(finding);
    }
}
