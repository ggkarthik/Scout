package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.aisecurity.azure.AiSecurityAzureConnectorService;
import com.prototype.vulnwatch.aisecurity.copilot.CopilotStudioConnectorService;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Refresh stale policy evidence through the existing connector admission and job deduplication path. */
@Service
public class AiGridDiscoveryRefreshService {
    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectProvider<AiSecurityAwsConnectorService> aws;
    private final ObjectProvider<AiSecurityAzureConnectorService> azure;
    private final ObjectProvider<CopilotStudioConnectorService> copilot;

    public AiGridDiscoveryRefreshService(NamedParameterJdbcTemplate jdbc,
            ObjectProvider<AiSecurityAwsConnectorService> aws,ObjectProvider<AiSecurityAzureConnectorService> azure,
            ObjectProvider<CopilotStudioConnectorService> copilot) {
        this.jdbc=jdbc; this.aws=aws; this.azure=azure; this.copilot=copilot;
    }

    public void requestStaleEvidence(Tenant tenant) {
        List<String> providers=jdbc.query("""
                select distinct provider from ai_grid_current_expected_candidates
                 where evidence_readiness='STALE' and selection in ('ENABLED','REQUIRED') order by provider
                """,(rs,row) -> rs.getString(1));
        for (String provider:providers) {
            try {
                if ("AWS".equals(provider)) aws.getObject().trigger(tenant,"system:policy-evidence-refresh");
                else if ("AZURE".equals(provider)) {
                    for (var connector:azure.getObject().list(tenant)) {
                        if (connector.enabled()) azure.getObject().trigger(tenant,connector.id(),"system:policy-evidence-refresh");
                    }
                } else if ("MICROSOFT_COPILOT".equals(provider)) {
                    for (var connector:copilot.getObject().list(tenant)) {
                        if (connector.discoveryEnabled() && !connector.killSwitch())
                            copilot.getObject().trigger(tenant,connector.id(),"system:policy-evidence-refresh");
                    }
                }
            } catch (ResponseStatusException error) {
                // Admission can be unavailable (disabled connector or missing credential); keep the stale setup action.
                if (error.getStatusCode().is5xxServerError()) throw error;
            }
        }
    }
}
