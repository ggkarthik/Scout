package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "app.tenancy.enforce-schema-version", havingValue = "true")
public class TenantSchemaReadinessHealthIndicator implements HealthIndicator {

    private final TenantSchemaStatusService service;
    private final int minimumVersion;

    public TenantSchemaReadinessHealthIndicator(
            TenantSchemaStatusService service,
            @Value("${app.tenancy.minimum-compatible-schema-version:44}") int minimumVersion
    ) {
        this.service = service;
        this.minimumVersion = minimumVersion;
    }

    @Override
    public Health health() {
        try {
            long failures = service.readinessFailures(minimumVersion);
            return failures == 0
                    ? Health.up().withDetail("minimumCompatibleVersion", minimumVersion).build()
                    : Health.down().withDetail("unreadyTenantCount", failures)
                            .withDetail("minimumCompatibleVersion", minimumVersion).build();
        } catch (RuntimeException ex) {
            return Health.down().withDetail("reason", "tenant schema control plane unavailable").build();
        }
    }
}
