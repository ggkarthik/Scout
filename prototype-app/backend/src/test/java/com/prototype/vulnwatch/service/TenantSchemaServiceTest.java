package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;

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
    void ensureSchemaExistsProvisionsEachSchemaOnlyOncePerProcess() {
        when(platformJdbcTemplate.queryForList(anyString(), org.mockito.ArgumentMatchers.eq(String.class), anyString(), anyString()))
                .thenReturn(List.of());

        service.ensureSchemaExists("tenant_acme");
        service.ensureSchemaExists("tenant_acme");

        verify(platformJdbcTemplate, times(1)).execute("CREATE SCHEMA IF NOT EXISTS \"tenant_acme\"");
        verify(platformJdbcTemplate, times(1))
                .queryForList(anyString(), org.mockito.ArgumentMatchers.eq(String.class), anyString(), anyString());
    }
}
