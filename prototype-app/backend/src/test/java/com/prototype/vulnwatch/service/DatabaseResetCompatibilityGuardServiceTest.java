package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class DatabaseResetCompatibilityGuardServiceTest {

    @Mock
    private JdbcTemplate platformJdbcTemplate;

    @Test
    void failsFastWhenLegacyFlywayHistoryIsPresent() {
        when(platformJdbcTemplate.queryForList(
                contains("table_name = 'flyway_schema_history'"),
                eq(String.class))).thenReturn(java.util.List.of("tenant_default"));
        when(platformJdbcTemplate.queryForObject(
                contains("\"tenant_default\".flyway_schema_history"),
                eq(Integer.class))).thenReturn(3);

        DatabaseResetCompatibilityGuardService guard =
                new DatabaseResetCompatibilityGuardService(platformJdbcTemplate, true);

        assertThrows(IllegalStateException.class, guard::verifyResetLineCompatibility);
    }

    @Test
    void failsFastWhenLegacySharedTablesExistInPublicSchema() {
        when(platformJdbcTemplate.queryForList(
                contains("table_name = 'flyway_schema_history'"),
                eq(String.class))).thenReturn(java.util.List.of("tenant_default"));
        when(platformJdbcTemplate.queryForObject(
                contains("\"tenant_default\".flyway_schema_history"),
                eq(Integer.class))).thenReturn(0);
        when(platformJdbcTemplate.queryForObject(
                contains("table_schema = 'public'"),
                eq(Integer.class))).thenReturn(2);

        DatabaseResetCompatibilityGuardService guard =
                new DatabaseResetCompatibilityGuardService(platformJdbcTemplate, true);

        assertThrows(IllegalStateException.class, guard::verifyResetLineCompatibility);
    }

    @Test
    void allowsFreshResetLineDatabase() {
        when(platformJdbcTemplate.queryForList(
                contains("table_name = 'flyway_schema_history'"),
                eq(String.class))).thenReturn(java.util.List.of("tenant_default"));
        when(platformJdbcTemplate.queryForObject(
                contains("\"tenant_default\".flyway_schema_history"),
                eq(Integer.class))).thenReturn(0);
        when(platformJdbcTemplate.queryForObject(
                contains("table_schema = 'public'"),
                eq(Integer.class))).thenReturn(0);

        DatabaseResetCompatibilityGuardService guard =
                new DatabaseResetCompatibilityGuardService(platformJdbcTemplate, true);

        assertDoesNotThrow(guard::verifyResetLineCompatibility);
        verifyNoMoreInteractions(platformJdbcTemplate);
    }
}
