package com.prototype.vulnwatch.aisecurity.aws;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityDiscoveryProvider;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.IngestionJobService;
import java.util.UUID;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.exception.SdkServiceException;
import software.amazon.awssdk.services.sts.model.StsException;

@Component
public class AwsBedrockDiscoveryProvider implements AiSecurityDiscoveryProvider {

    private final AwsBedrockDiscoveryService discovery;

    public AwsBedrockDiscoveryProvider(AwsBedrockDiscoveryService discovery) {
        this.discovery = discovery;
    }

    @Override
    public String provider() {
        return "AWS";
    }

    @Override
    public String jobType() {
        return IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK;
    }

    @Override
    public Object discover(Tenant tenant, UUID connectorId) {
        return discovery.discover(tenant, connectorId);
    }

    @Override
    public String failureCode(Exception exception) {
        if (exception instanceof StsException) {
            return "ASSUME_ROLE_FAILED";
        }
        if (exception instanceof SdkServiceException serviceException
                && serviceException.statusCode() == 429) {
            return "THROTTLED";
        }
        if (exception instanceof AiSecurityAwsAdmissionService.AdmissionException) {
            return "THROTTLED";
        }
        return AiSecurityDiscoveryProvider.super.failureCode(exception);
    }

    @Override
    public String safeFailureMessage(String code) {
        return switch (code) {
            case "ASSUME_ROLE_FAILED" -> "Unable to assume the configured AWS role";
            case "THROTTLED" -> "AWS temporarily throttled the AI Security scan";
            default -> AiSecurityDiscoveryProvider.super.safeFailureMessage(code);
        };
    }
}
