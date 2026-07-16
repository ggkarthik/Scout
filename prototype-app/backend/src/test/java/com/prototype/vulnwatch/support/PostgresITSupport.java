package com.prototype.vulnwatch.support;

import java.util.Base64;
import org.springframework.test.context.DynamicPropertyRegistry;

/**
 * Shared constants and helpers for Postgres integration tests.
 *
 * <p>The constants here mirror the values baked into
 * {@link PostgresIntegrationTest} / {@link PostgresControllerIntegrationTest}
 * so that test code (e.g. {@link AuthRequest}) and the Spring
 * {@code @SpringBootTest properties} stay in sync from a single source.
 */
public final class PostgresITSupport {

    /** Bound to {@code app.security.api-key} via the composed annotations. */
    public static final String API_KEY = "test-api-key";

    /** Bound to {@code app.security.creator-key} via the composed annotations. */
    public static final String CREATOR_KEY = "test-creator-key";

    /** Default {@code X-User-ID} for analyst-style requests. */
    public static final String DEFAULT_USER_ID = "test-user";

    /** Default {@code X-Tenant-ID} header value matching legacy single-tenant runtime. */
    public static final String DEFAULT_TENANT_ID = "1";

    private PostgresITSupport() {
    }

    /**
     * Wires the per-class {@link LocalPostgresTestDatabase.DatabaseConfig} into
     * the Spring environment. Call from a static
     * {@code @DynamicPropertySource} method on the test class.
     */
    public static void registerDatabaseProperties(
            DynamicPropertyRegistry registry,
            LocalPostgresTestDatabase.DatabaseConfig database) {
        registry.add("DB_URL", database::url);
        registry.add("DB_USERNAME", database::username);
        registry.add("DB_PASSWORD", database::password);
        // The integration suite caches many application contexts. Keep each test
        // pool deliberately small so the suite cannot exhaust PostgreSQL clients.
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> "5");
        registry.add("spring.datasource.hikari.minimum-idle", () -> "0");
        registry.add("app.scheduling.enabled", () -> "false");
        registry.add("app.schema-migration.legacy-test-runner-enabled", () -> "true");
        registry.add("app.security.credential-encryption-key",
                () -> Base64.getEncoder().encodeToString(new byte[32]));
    }
}
