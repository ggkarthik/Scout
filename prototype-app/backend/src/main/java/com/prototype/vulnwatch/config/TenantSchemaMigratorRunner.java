package com.prototype.vulnwatch.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "app.schema-migration.enabled", havingValue = "true")
public class TenantSchemaMigratorRunner {

    private static final Logger LOG = LoggerFactory.getLogger(TenantSchemaMigratorRunner.class);

    private final TenantSchemaMigrationService migrationService;
    private final ObjectMapper objectMapper;
    private final boolean reportOnly;
    private final boolean exitAfterRun;
    private final ConfigurableApplicationContext applicationContext;

    public TenantSchemaMigratorRunner(
            TenantSchemaMigrationService migrationService,
            ObjectMapper objectMapper,
            @Value("${app.schema-migration.report-only:false}") boolean reportOnly,
            @Value("${app.schema-migration.exit-after-run:false}") boolean exitAfterRun,
            ConfigurableApplicationContext applicationContext
    ) {
        this.migrationService = migrationService;
        this.objectMapper = objectMapper;
        this.reportOnly = reportOnly;
        this.exitAfterRun = exitAfterRun;
        this.applicationContext = applicationContext;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Order(100)
    public void migrate() throws Exception {
        var report = migrationService.migrateAll(reportOnly);
        LOG.info("tenant_schema_migration_report={}", objectMapper.writeValueAsString(report));
        if (!report.success()) {
            throw new IllegalStateException("Tenant schema migration failed: " + report.failureCode());
        }
        if (exitAfterRun) {
            LOG.info("Tenant schema migration completed; scheduling migration-job application context shutdown");
            Thread shutdownThread = new Thread(() -> {
                try {
                    // Let Spring finish publishing ApplicationReadyEvent before
                    // closing its bean factory. Closing synchronously from this
                    // listener makes the remaining listeners fail against an
                    // already-closed context and turns a successful migration
                    // into a non-zero process exit.
                    Thread.sleep(250);
                } catch (InterruptedException ex) {
                    Thread.currentThread().interrupt();
                }
                SpringApplication.exit(applicationContext, () -> 0);
            }, "schema-migrator-shutdown");
            shutdownThread.setDaemon(false);
            shutdownThread.start();
        }
    }
}
