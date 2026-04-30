package com.prototype.vulnwatch.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class CpeUtilTest {

    @Test
    void normalizeCpe23ProducesCanonicalForm() {
        String normalized = CpeUtil.normalizeCpe23("CPE:2.3:A:NGINX:NGINX:1.23.0:-:*:*:*:*:*:*");
        assertEquals("cpe:2.3:a:nginx:nginx:1.23.0:*:*:*:*:*:*:*", normalized);
    }

    @Test
    void normalizeCpe23PreservesWildcard() {
        // A valid CPE 2.3 string has exactly 11 attributes (13 total segments including cpe:2.3: prefix).
        String normalized = CpeUtil.normalizeCpe23("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*");
        assertEquals("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", normalized);
    }
}
