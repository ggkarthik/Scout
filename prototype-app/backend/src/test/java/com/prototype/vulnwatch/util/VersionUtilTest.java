package com.prototype.vulnwatch.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.domain.VersionScheme;
import org.junit.jupiter.api.Test;

class VersionUtilTest {

    @Test
    void matchesExactVersionWithPrefixNormalization() {
        assertTrue(VersionUtil.matches("v1.2.3", "1.2.3", null, null, null, null));
    }

    @Test
    void respectsInclusiveExclusiveBounds() {
        assertTrue(VersionUtil.matches("2.0.0", null, "1.9.0", true, "2.0.0", true));
        assertFalse(VersionUtil.matches("2.0.0", null, "2.0.0", false, "3.0.0", true));
        assertFalse(VersionUtil.matches("2.0.0", null, "1.0.0", true, "2.0.0", false));
    }

    @Test
    void comparesPreReleaseLowerThanRelease() {
        assertTrue(VersionUtil.compare("1.0.0-rc1", "1.0.0") < 0);
    }

    @Test
    void comparesPep440VersionsDeterministically() {
        assertTrue(VersionUtil.compare("1.0rc1", "1.0", VersionScheme.PEP440) < 0);
        assertTrue(VersionUtil.compare("1.0", "1.0.post1", VersionScheme.PEP440) < 0);
        assertEquals(0, VersionUtil.compare("v1.2.3", "1.2.3", VersionScheme.PEP440));
    }

    @Test
    void comparesDpkgVersionsDeterministically() {
        assertTrue(VersionUtil.compare("1:1.0-1", "1:1.0-2", VersionScheme.DPKG) < 0);
        assertTrue(VersionUtil.compare("2:1.0-1", "1:9.9-9", VersionScheme.DPKG) > 0);
        assertTrue(VersionUtil.compare("1.0~rc1-1", "1.0-1", VersionScheme.DPKG) < 0);
    }

    @Test
    void comparesRpmVersionsDeterministically() {
        assertTrue(VersionUtil.compare("1.0-1", "1.0-2", VersionScheme.RPM) < 0);
        assertTrue(VersionUtil.compare("2.0", "10.0", VersionScheme.RPM) < 0);
        assertTrue(VersionUtil.compare("1.0~beta", "1.0", VersionScheme.RPM) < 0);
    }
}
