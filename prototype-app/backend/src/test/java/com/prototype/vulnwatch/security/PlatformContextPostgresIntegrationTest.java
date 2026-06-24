package com.prototype.vulnwatch.security;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class PlatformContextPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("platform_context");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private SyncRunRepository syncRunRepository;

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void platformContextUsesPlatformOnlySearchPathAndFailsOnUnqualifiedTenantTables() {
        TenantContext.runAsPlatform(() -> {
            assertThatCode(() -> jdbcTemplate.queryForObject("select count(*) from platform.tenants", Long.class))
                    .doesNotThrowAnyException();

            SyncRun run = new SyncRun();
            run.setSyncType("PLATFORM_CONTEXT_IT");
            run.setStatus("running");
            SyncRun saved = syncRunRepository.saveAndFlush(run);

            assertThat(syncRunRepository.findById(saved.getId())).isPresent();

            assertThatThrownBy(() -> jdbcTemplate.queryForObject("select count(*) from assets", Long.class))
                    .isInstanceOf(BadSqlGrammarException.class)
                    .hasMessageContaining("relation \"assets\" does not exist");
        });
    }
}
