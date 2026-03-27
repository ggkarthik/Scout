package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.dto.PrototypeDataResetResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.JdbcTemplate;

@ExtendWith(MockitoExtension.class)
class PrototypeDataResetServiceTest {

    @Mock
    private JdbcTemplate jdbcTemplate;

    @Mock
    private VulnerabilityIntelSummaryService vulnerabilityIntelSummaryService;

    private PrototypeDataResetService service;

    @BeforeEach
    void setUp() {
        service = new PrototypeDataResetService(vulnerabilityIntelSummaryService, jdbcTemplate);
    }

    @Test
    void cleansExpandedPrototypeDataTablesAndFallsBackToDeleteWhenTruncateFails() {
        when(jdbcTemplate.execute(Mockito.<ConnectionCallback<String>>any()))
                .thenReturn("PostgreSQL");
        when(jdbcTemplate.queryForObject(
                argThat(sql -> sql != null && sql.startsWith("select count(*) from information_schema.tables")),
                eq(Long.class),
                anyString()))
                .thenReturn(1L);
        when(jdbcTemplate.queryForObject(
                argThat(sql -> sql != null
                        && sql.startsWith("select count(*) from ")
                        && !sql.contains("information_schema.tables")),
                eq(Long.class)))
                .thenReturn(0L);

        Mockito.doAnswer(invocation -> {
                    String sql = invocation.getArgument(0, String.class);
                    if ("truncate table vex_assertions restart identity cascade".equals(sql)) {
                        throw new DataAccessResourceFailureException("truncate failed");
                    }
                    return null;
                })
                .when(jdbcTemplate)
                .execute(anyString());

        PrototypeDataResetResponse response = service.cleanAll();

        assertTrue(response.deletedRows().containsKey("component_vulnerability_states"));
        assertTrue(response.deletedRows().containsKey("vex_assertions"));
        assertTrue(response.deletedRows().containsKey("investigations"));
        assertTrue(response.deletedRows().containsKey("applicability_assessments"));
        assertTrue(response.deletedRows().containsKey("finding_delta_queue"));
        assertTrue(response.deletedRows().containsKey("software_eol_mapping"));
        assertTrue(response.deletedRows().containsKey("eol_release"));
        assertTrue(response.deletedRows().containsKey("eol_product_catalog"));
        assertTrue(response.deletedRows().containsKey("vulnerability_source_context"));
        assertTrue(response.deletedRows().containsKey("vulnerability_threat_overlays"));

        verify(jdbcTemplate).execute("truncate table component_vulnerability_states restart identity cascade");
        verify(jdbcTemplate).execute("truncate table investigations restart identity cascade");
        verify(jdbcTemplate).execute("truncate table applicability_assessments restart identity cascade");
        verify(jdbcTemplate).execute("truncate table software_eol_mapping restart identity cascade");
        verify(jdbcTemplate).execute("truncate table eol_release restart identity cascade");
        verify(jdbcTemplate).execute("truncate table eol_product_catalog restart identity cascade");
        verify(jdbcTemplate).update("delete from vex_assertions");
        verify(jdbcTemplate, never()).execute("truncate table component_vulnerability_state");
        verify(vulnerabilityIntelSummaryService).resetReadModelCaches();
    }
}
