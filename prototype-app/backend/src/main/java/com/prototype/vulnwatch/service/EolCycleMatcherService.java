package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.EolRelease;
import com.prototype.vulnwatch.repo.EolReleaseRepository;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Matches an installed software version string to the appropriate EOL release cycle.
 *
 * Resolution strategy (in order):
 * 1. Exact cycle match: version == cycle (e.g. "22.04" → cycle "22.04")
 * 2. Major.minor prefix match: strip patch from version, match cycle prefix
 *    (e.g. "3.11.5" → cycle "3.11", "22.04.1" → cycle "22.04")
 * 3. Major-only prefix match: match by major version (e.g. "8.0.33" → cycle "8")
 * 4. Highest cycle ≤ installed version: semver-aware fallback
 */
@Service
public class EolCycleMatcherService {

    private static final Logger LOG = LoggerFactory.getLogger(EolCycleMatcherService.class);

    private static final Pattern VERSION_PATTERN = Pattern.compile("^(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?.*");

    private final EolReleaseRepository eolReleaseRepository;

    public EolCycleMatcherService(EolReleaseRepository eolReleaseRepository) {
        this.eolReleaseRepository = eolReleaseRepository;
    }

    /**
     * Finds the best matching EOL release cycle for the given product slug and version string.
     *
     * @return the matched EolRelease, or empty if no suitable cycle found
     */
    public Optional<EolRelease> matchCycle(String productSlug, String version) {
        if (productSlug == null || productSlug.isBlank() || version == null || version.isBlank()) {
            return Optional.empty();
        }

        List<EolRelease> cycles = eolReleaseRepository.findByProductSlug(productSlug);
        if (cycles.isEmpty()) {
            return Optional.empty();
        }

        String cleanVersion = version.trim().toLowerCase(Locale.ROOT);

        // Step 1: Exact match
        Optional<EolRelease> exact = cycles.stream()
                .filter(r -> r.getCycle().equalsIgnoreCase(cleanVersion))
                .findFirst();
        if (exact.isPresent()) {
            return exact;
        }

        // Step 2: Major.minor prefix match
        String majorMinor = extractMajorMinor(cleanVersion);
        if (majorMinor != null) {
            Optional<EolRelease> mm = cycles.stream()
                    .filter(r -> r.getCycle().equalsIgnoreCase(majorMinor))
                    .findFirst();
            if (mm.isPresent()) {
                return mm;
            }
        }

        // Step 3: Major-only match
        String major = extractMajor(cleanVersion);
        if (major != null) {
            Optional<EolRelease> maj = cycles.stream()
                    .filter(r -> r.getCycle().equalsIgnoreCase(major))
                    .findFirst();
            if (maj.isPresent()) {
                return maj;
            }
        }

        // Step 4: Highest cycle whose version is ≤ installed version (semver-aware)
        return cycles.stream()
                .filter(r -> compareVersions(r.getCycle(), cleanVersion) <= 0)
                .max((a, b) -> compareVersions(a.getCycle(), b.getCycle()));
    }

    // -------------------------------------------------------------------------
    // Version parsing helpers
    // -------------------------------------------------------------------------

    private String extractMajorMinor(String version) {
        Matcher m = VERSION_PATTERN.matcher(version);
        if (!m.matches()) {
            return null;
        }
        String major = m.group(1);
        String minor = m.group(2);
        if (minor == null) {
            return null;
        }
        return major + "." + minor;
    }

    private String extractMajor(String version) {
        Matcher m = VERSION_PATTERN.matcher(version);
        if (!m.matches()) {
            return null;
        }
        return m.group(1);
    }

    /**
     * Compares two version strings numerically.
     * Returns negative if a < b, 0 if equal, positive if a > b.
     */
    private int compareVersions(String a, String b) {
        int[] ta = parseVersionTuple(a);
        int[] tb = parseVersionTuple(b);
        for (int i = 0; i < Math.max(ta.length, tb.length); i++) {
            int va = i < ta.length ? ta[i] : 0;
            int vb = i < tb.length ? tb[i] : 0;
            if (va != vb) {
                return Integer.compare(va, vb);
            }
        }
        return 0;
    }

    private int[] parseVersionTuple(String version) {
        if (version == null || version.isBlank()) {
            return new int[]{0};
        }
        // Strip any non-numeric suffix (e.g. "22.04-lts" → "22.04")
        String clean = version.replaceAll("[^0-9.].*$", "").trim();
        String[] parts = clean.split("\\.");
        int[] result = new int[parts.length];
        for (int i = 0; i < parts.length; i++) {
            try {
                result[i] = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                result[i] = 0;
            }
        }
        return result;
    }
}
