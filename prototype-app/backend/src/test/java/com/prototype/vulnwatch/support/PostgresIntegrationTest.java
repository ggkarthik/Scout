package com.prototype.vulnwatch.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

/**
 * Service- or repo-layer Postgres integration test. Brings in the standard app
 * properties and the {@code postgres} profile, gates execution behind the
 * {@code run.postgres.it} system property used by the {@code postgres-it} Maven
 * profile, but does NOT auto-configure {@code MockMvc} — use
 * {@link PostgresControllerIntegrationTest} for that.
 *
 * <p>Each test class still declares its own
 * {@link LocalPostgresTestDatabase#provision(String)} call and a
 * {@code @DynamicPropertySource} that calls
 * {@link PostgresITSupport#registerDatabaseProperties}.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(properties = {
        "app.security.api-key=" + PostgresITSupport.API_KEY,
        "app.security.creator-key=" + PostgresITSupport.CREATOR_KEY,
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
public @interface PostgresIntegrationTest {
}
