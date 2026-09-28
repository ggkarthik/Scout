package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.mock.env.MockEnvironment;

class LegacySharedConnectorConfigGuardTest {

    @Test
    void startsWhenNoSharedCredentialsAreSupplied() {
        assertDoesNotThrow(() -> new LegacySharedConnectorConfigGuard(new MockEnvironment()));
    }

    @Test
    void refusesToStartWhenAServiceNowInstanceIsSharedAcrossTenants() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("CMDB_SERVICENOW_BASE_URL", "https://shared.service-now.com");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new LegacySharedConnectorConfigGuard(environment));

        assertTrue(failure.getMessage().contains("CMDB_SERVICENOW_BASE_URL"), failure.getMessage());
        assertTrue(failure.getMessage().contains("per tenant"), failure.getMessage());
    }

    @Test
    void refusesToStartWhenASccmDatabaseIsSharedAcrossTenants() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("SCCM_JDBC_URL", "jdbc:sqlserver://shared:1433");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new LegacySharedConnectorConfigGuard(environment));

        assertTrue(failure.getMessage().contains("SCCM_JDBC_URL"), failure.getMessage());
    }

    @Test
    void namesEveryOffendingVariableSoOneRestartClearsThemAll() {
        MockEnvironment environment = new MockEnvironment()
                .withProperty("CMDB_SERVICENOW_BASE_URL", "https://shared.service-now.com")
                .withProperty("CMDB_SERVICENOW_USERNAME", "svc")
                .withProperty("SCCM_JDBC_URL", "jdbc:sqlserver://shared:1433");

        IllegalStateException failure = assertThrows(IllegalStateException.class,
                () -> new LegacySharedConnectorConfigGuard(environment));

        assertTrue(failure.getMessage().contains("CMDB_SERVICENOW_BASE_URL"), failure.getMessage());
        assertTrue(failure.getMessage().contains("CMDB_SERVICENOW_USERNAME"), failure.getMessage());
        assertTrue(failure.getMessage().contains("SCCM_JDBC_URL"), failure.getMessage());
    }

    /**
     * The old mock-mode flag defaulted to false, so deployments may still pass it explicitly
     * disabled. That is not a shared instance and must not block startup.
     */
    @Test
    void toleratesTheMockModeFlagLeftExplicitlyDisabled() {
        MockEnvironment environment = new MockEnvironment().withProperty("SCCM_MOCK_MODE", "false");

        assertDoesNotThrow(() -> new LegacySharedConnectorConfigGuard(environment));
    }

    @Test
    void refusesToStartWhenMockModeIsEnabledDeploymentWide() {
        MockEnvironment environment = new MockEnvironment().withProperty("SCCM_MOCK_MODE", "true");

        assertThrows(IllegalStateException.class, () -> new LegacySharedConnectorConfigGuard(environment));
    }
}
