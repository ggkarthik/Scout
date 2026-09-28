package com.prototype.vulnwatch.config;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Refuses to start when a deployment still supplies shared CMDB credentials.
 *
 * <p>ServiceNow and SCCM used to fall back to deployment-wide environment variables whenever a
 * tenant had no connector row of its own. In a multi-tenant deployment that pointed every
 * unconfigured tenant at one instance, so their CI lookups, incidents and inventory queries
 * ran against another organisation's system. Those fallbacks are gone and configuration is
 * strictly per tenant.
 *
 * <p>This fails loudly rather than ignoring the variables. Ignoring them silently is the
 * dangerous outcome: an operator who set {@code CMDB_SERVICENOW_BASE_URL} believes ServiceNow
 * is configured, and would discover otherwise only when incidents stopped being raised.
 */
@Component
public class LegacySharedConnectorConfigGuard {

    /** Variable name to the connector whose per-tenant configuration replaces it. */
    private static final Map<String, String> REMOVED_VARIABLES = Map.of(
            "CMDB_SERVICENOW_BASE_URL", "ServiceNow",
            "CMDB_SERVICENOW_USERNAME", "ServiceNow",
            "CMDB_SERVICENOW_PASSWORD", "ServiceNow",
            "SCCM_JDBC_URL", "SCCM/MECM",
            "SCCM_USERNAME", "SCCM/MECM",
            "SCCM_PASSWORD", "SCCM/MECM",
            "SCCM_MOCK_MODE", "SCCM/MECM"
    );

    public LegacySharedConnectorConfigGuard(Environment environment) {
        List<String> present = new ArrayList<>();
        REMOVED_VARIABLES.keySet().stream().sorted().forEach(variable -> {
            String value = environment.getProperty(variable);
            if (value != null && !value.isBlank() && !"false".equalsIgnoreCase(value.trim())) {
                present.add(variable + " (" + REMOVED_VARIABLES.get(variable) + ")");
            }
        });
        if (!present.isEmpty()) {
            throw new IllegalStateException(
                    "Shared CMDB credentials are no longer supported: " + String.join(", ", present)
                            + ". Connector configuration is per tenant — remove these variables and "
                            + "configure each tenant's connector under Connect → Sources. A shared "
                            + "instance would serve every unconfigured tenant from one system.");
        }
    }
}
