package com.prototype.vulnwatch.migration;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.stereotype.Component;

/** Resolves the independently versioned platform and tenant Flyway catalogs. */
@Component
public final class PackagedMigrationCatalog {

    public static final String PLATFORM_LOCATION = "db/migration/postgres_reset";
    public static final String TENANT_LOCATION = "db/migration/tenant";
    private static final Pattern VERSIONED_MIGRATION = Pattern.compile("^V([0-9]+)__.+\\.sql$");

    private final Targets targets;

    public PackagedMigrationCatalog() {
        this(resolve());
    }

    PackagedMigrationCatalog(Targets targets) {
        this.targets = targets;
    }

    public int platformTarget() {
        return targets.platformTarget();
    }

    public int tenantTarget() {
        return targets.tenantTarget();
    }

    public static Targets resolve() {
        return new Targets(latest(PLATFORM_LOCATION), latest(TENANT_LOCATION));
    }

    static int latest(String location) {
        Resource[] resources;
        try {
            resources = new PathMatchingResourcePatternResolver()
                    .getResources("classpath*:" + location + "/V*.sql");
        } catch (IOException ex) {
            throw new IllegalStateException("Unable to inspect packaged migrations at " + location, ex);
        }
        if (resources.length == 0) {
            throw new IllegalStateException("No packaged migrations found at " + location);
        }

        Map<Integer, String> filesByVersion = new HashMap<>();
        int latest = 0;
        for (Resource resource : resources) {
            String filename = resource.getFilename();
            Matcher matcher = VERSIONED_MIGRATION.matcher(filename == null ? "" : filename);
            if (!matcher.matches()) {
                throw new IllegalStateException("Malformed packaged migration name at " + location + ": " + filename);
            }
            int version = Integer.parseInt(matcher.group(1));
            String duplicate = filesByVersion.putIfAbsent(version, filename);
            if (duplicate != null) {
                throw new IllegalStateException("Duplicate packaged migration version V" + version
                        + " at " + location + ": " + duplicate + ", " + filename);
            }
            latest = Math.max(latest, version);
        }
        return latest;
    }

    public record Targets(int platformTarget, int tenantTarget) {
    }
}
