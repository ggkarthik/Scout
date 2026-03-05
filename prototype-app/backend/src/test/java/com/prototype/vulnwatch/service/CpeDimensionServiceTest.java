package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.domain.CpeDim;
import com.prototype.vulnwatch.util.CpeUtil;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "spring.datasource.url=jdbc:h2:mem:cpe_dim;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "app.correlation.backfill-targets-on-startup=false"
})
@Transactional
class CpeDimensionServiceTest {

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

    @Test
    void normalizeCpe23ProducesCanonicalForm() {
        String normalized = CpeUtil.normalizeCpe23("CPE:2.3:A:NGINX:NGINX:1.23.0:-:*:*:*:*:*:*");
        assertEquals("cpe:2.3:a:nginx:nginx:1.23.0:*:*:*:*:*:*:*", normalized);
    }
}
