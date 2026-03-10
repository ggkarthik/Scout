package com.prototype.vulnwatch.util;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class CpeUtilTest {

    @Test
    void normalizeCpe23ProducesCanonicalForm() {
        String normalized = CpeUtil.normalizeCpe23("CPE:2.3:A:NGINX:NGINX:1.23.0:-:*:*:*:*:*:*");
        assertEquals("cpe:2.3:a:nginx:nginx:1.23.0:*:*:*:*:*:*:*", normalized);
    }
}
