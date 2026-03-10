package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false"
})
@ActiveProfiles("postgres")
@Transactional
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CpeDimensionServicePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cpe_dimension_service");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private CpeDimensionService cpeDimensionService;

    @Test
    void resolveOrCreateIsStableForEquivalentCpes() {
        CpeDim first = cpeDimensionService.resolveOrCreate("CPE:2.3:A:Apache:Log4j:2.14.1:-:*:*:*:*:*:*");
        CpeDim second = cpeDimensionService.resolveOrCreate("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*");

        assertNotNull(first);
        assertNotNull(second);
        assertEquals(first.getId(), second.getId());
        assertEquals("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*", second.getNormalizedCpe());
        assertEquals("a|apache|log4j", second.getCpeKey());
    }
}
