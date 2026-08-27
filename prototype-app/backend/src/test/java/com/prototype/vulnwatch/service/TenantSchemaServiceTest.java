package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.eq;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import java.util.List;

@ExtendWith(MockitoExtension.class)
class TenantSchemaServiceTest {

    @Mock
    private JdbcTemplate platformJdbcTemplate;

    private TenantSchemaService service;

    @BeforeEach
    void setUp() {
        service = new TenantSchemaService(platformJdbcTemplate, "tenant_default");
    }

    @Test
    void ensureSchemaExistsFailsClosedWithoutExecutingDdl() {
        when(platformJdbcTemplate.queryForObject(anyString(), eq(Boolean.class), anyString()))
                .thenReturn(false);

        assertThrows(IllegalStateException.class, () -> service.ensureSchemaExists("tenant_acme"));

        verify(platformJdbcTemplate, never()).execute(anyString());
    }

    @Test
    @SuppressWarnings("unchecked")
    void assertSchemaReadyReportsMissingCurrentProjectionClearly() {
        ReflectionTestUtils.setField(service, "enforceSchemaVersion", true);
        ReflectionTestUtils.setField(service, "minimumCompatibleSchemaVersion", 53);
        when(platformJdbcTemplate.queryForObject(anyString(), eq(Boolean.class), anyString())).thenReturn(true);
        when(platformJdbcTemplate.query(anyString(), any(org.springframework.jdbc.core.RowMapper.class), anyString()))
                .thenReturn(List.of());

        IllegalStateException failure = assertThrows(
                IllegalStateException.class, () -> service.assertSchemaReady("tenant_acme"));

        org.junit.jupiter.api.Assertions.assertTrue(failure.getMessage().contains("no readiness projection"));
    }
}
