package com.prototype.vulnwatch.config;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import javax.sql.DataSource;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.flyway.FlywayMigrationStrategy;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

/** Test-harness equivalent of the production platform-then-tenant bootstrap, executed before JPA. */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "app.schema-migration.pre-jpa-default-tenant-enabled", havingValue = "true")
public class PreJpaDefaultTenantMigrationConfiguration {
    private static final String DEFAULT_SCHEMA = "tenant_default";
    private static final UUID DEFAULT_TENANT_ID = UUID.nameUUIDFromBytes(
            "scout-default-tenant".getBytes(StandardCharsets.UTF_8));

    @Bean
    FlywayMigrationStrategy platformThenDefaultTenantMigrationStrategy() {
        return platformFlyway -> {
            platformFlyway.migrate();
            DataSource dataSource = platformFlyway.getConfiguration().getDataSource();
            JdbcTemplate jdbc = new JdbcTemplate(dataSource);
            jdbc.update("""
                    insert into platform.tenants (
                        id,name,slug,schema_name,status,plan_code,created_at,updated_at,
                        max_connector_count,max_service_account_count,max_daily_sbom_uploads,
                        max_export_rows,max_daily_exposure_refreshes)
                    values (?, 'Default Workspace', 'default-workspace', ?, 'ACTIVE', 'ENTERPRISE',
                            now(), now(), 10, 25, 100, 50000, 25)
                    on conflict (id) do nothing
                    """, DEFAULT_TENANT_ID, DEFAULT_SCHEMA);
            Flyway.configure().dataSource(dataSource).schemas(DEFAULT_SCHEMA).defaultSchema(DEFAULT_SCHEMA)
                    .table("tenant_schema_history").locations("classpath:db/migration/tenant")
                    .baselineOnMigrate(true).baselineVersion(MigrationVersion.fromVersion("41"))
                    .baselineDescription("legacy tenant schema baseline")
                    .placeholders(Map.of("tenantId", DEFAULT_TENANT_ID.toString(), "tenantSchema", DEFAULT_SCHEMA))
                    .validateOnMigrate(true).outOfOrder(false).load().migrate();
        };
    }
}
