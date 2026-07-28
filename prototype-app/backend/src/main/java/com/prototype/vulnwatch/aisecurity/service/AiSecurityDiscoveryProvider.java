package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;

public interface AiSecurityDiscoveryProvider {

    String provider();

    String jobType();

    Object discover(Tenant tenant, UUID connectorId);

    default String failureCode(Exception exception) {
        return "PROVIDER_UNAVAILABLE";
    }

    default String safeFailureMessage(String code) {
        return "AI Security discovery could not be completed";
    }
}
