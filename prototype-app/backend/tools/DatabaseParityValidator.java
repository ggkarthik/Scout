import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.List;
import java.util.Locale;

public final class DatabaseParityValidator {

    private static final String DEFAULT_H2_URL =
            "jdbc:h2:file:./data/archive/h2-archive-20260308-postgres-cutover/vulnwatch;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH";
    private static final String DEFAULT_H2_USER = "sa";
    private static final String DEFAULT_H2_PASSWORD = "";
    private static final String DEFAULT_POSTGRES_URL = "jdbc:postgresql://localhost:5432/vulnwatch";

    private static final List<QueryCheck> CHECKS = List.of(
            new QueryCheck("tenants", "select count(*) from tenants"),
            new QueryCheck("risk_policies", "select count(*) from risk_policies"),
            new QueryCheck("assets", "select count(*) from assets"),
            new QueryCheck("sbom_uploads", "select count(*) from sbom_uploads"),
            new QueryCheck("inventory_components", "select count(*) from inventory_components"),
            new QueryCheck("inventory_components.active",
                    "select count(*) from inventory_components where component_status = 'ACTIVE'"),
            new QueryCheck("inventory_components.retired",
                    "select count(*) from inventory_components where component_status = 'RETIRED'"),
            new QueryCheck("inventory_component_cpe_map", "select count(*) from inventory_component_cpe_map"),
            new QueryCheck("software_identities", "select count(*) from software_identities"),
            new QueryCheck("software_identifiers", "select count(*) from software_identifiers"),
            new QueryCheck("software_inventory_items", "select count(*) from software_inventory_items"),
            new QueryCheck("vulnerabilities", "select count(*) from vulnerabilities"),
            new QueryCheck("vulnerability_rules", "select count(*) from vulnerability_rules"),
            new QueryCheck("vulnerability_targets", "select count(*) from vulnerability_targets"),
            new QueryCheck("vulnerability_config_expr", "select count(*) from vulnerability_config_expr"),
            new QueryCheck("vulnerability_intel_observations", "select count(*) from vulnerability_intel_observations"),
            new QueryCheck("component_vulnerability_states", "select count(*) from component_vulnerability_states"),
            new QueryCheck("component_vulnerability_states.impacted",
                    "select count(*) from component_vulnerability_states where impact_state = 'IMPACTED'"),
            new QueryCheck("findings", "select count(*) from findings"),
            new QueryCheck("findings.open", "select count(*) from findings where status = 'OPEN'"),
            new QueryCheck("findings.resolved", "select count(*) from findings where status = 'RESOLVED'"),
            new QueryCheck("org_cve_records", "select count(*) from org_cve_records"),
            new QueryCheck("org_cve_records.impacted",
                    "select count(*) from org_cve_records where impacted = true"),
            new QueryCheck("sync_runs", "select count(*) from sync_runs"),
            new QueryCheck("github_sbom_sources", "select count(*) from github_sbom_sources"),
            new QueryCheck("investigations", "select count(*) from investigations"),
            new QueryCheck("applicability_assessments", "select count(*) from applicability_assessments")
    );

    private DatabaseParityValidator() {
    }

    public static void main(String[] args) throws Exception {
        Class.forName("org.h2.Driver");
        Class.forName("org.postgresql.Driver");

        String h2Url = property("h2.url", "H2_URL", DEFAULT_H2_URL);
        String h2User = property("h2.user", "H2_USER", DEFAULT_H2_USER);
        String h2Password = property("h2.password", "H2_PASSWORD", DEFAULT_H2_PASSWORD);

        String postgresUrl = property("postgres.url", "POSTGRES_URL", DEFAULT_POSTGRES_URL);
        String postgresUser = property("postgres.user", "POSTGRES_USER", System.getProperty("user.name"));
        String postgresPassword = property("postgres.password", "POSTGRES_PASSWORD", "");

        System.out.println("H2 URL: " + h2Url);
        System.out.println("Postgres URL: " + postgresUrl);
        System.out.println();
        System.out.printf("%-38s %12s %12s %12s%n", "check", "h2", "postgres", "status");
        System.out.println("-".repeat(78));

        boolean mismatch = false;
        try (Connection h2 = DriverManager.getConnection(h2Url, h2User, h2Password);
             Connection postgres = DriverManager.getConnection(postgresUrl, postgresUser, postgresPassword)) {
            for (QueryCheck check : CHECKS) {
                long h2Count = queryForCount(h2, check.sql());
                long postgresCount = queryForCount(postgres, check.sql());
                boolean matched = h2Count == postgresCount;
                if (!matched) {
                    mismatch = true;
                }
                System.out.printf(
                        Locale.ROOT,
                        "%-38s %12d %12d %12s%n",
                        check.label(),
                        h2Count,
                        postgresCount,
                        matched ? "MATCH" : "MISMATCH"
                );
            }
        }

        if (mismatch) {
            System.err.println();
            System.err.println("Database parity validation failed.");
            System.exit(1);
        }

        System.out.println();
        System.out.println("Database parity validation passed.");
    }

    private static long queryForCount(Connection connection, String sql) throws Exception {
        try (Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getLong(1);
        }
    }

    private static String property(String systemName, String envName, String defaultValue) {
        String system = System.getProperty(systemName);
        if (system != null && !system.isBlank()) {
            return system;
        }
        String env = System.getenv(envName);
        if (env != null && !env.isBlank()) {
            return env;
        }
        return defaultValue;
    }

    private record QueryCheck(String label, String sql) {
    }
}
