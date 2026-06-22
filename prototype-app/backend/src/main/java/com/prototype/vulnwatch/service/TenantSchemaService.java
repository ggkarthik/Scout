package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.sql.ResultSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ConnectionCallback;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;

@Service
public class TenantSchemaService {

    private static final String FLYWAY_HISTORY_TABLE = "flyway_schema_history";

    private final JdbcTemplate platformJdbcTemplate;
    private final String defaultSchemaName;
    private final ConcurrentMap<String, Object> schemaProvisionLocks = new ConcurrentHashMap<>();
    private final Set<String> provisionedSchemas = ConcurrentHashMap.newKeySet();

    public TenantSchemaService(
            @Qualifier("platformJdbcTemplate") JdbcTemplate platformJdbcTemplate,
            @Value("${app.tenancy.default-schema:tenant_default}") String defaultSchemaName
    ) {
        this.platformJdbcTemplate = platformJdbcTemplate;
        this.defaultSchemaName = defaultSchemaName;
    }

    public String defaultSchemaName() {
        return defaultSchemaName;
    }

    public String normalizeSchemaName(String schemaName) {
        return sanitizeSchemaName(schemaName);
    }

    public String schemaNameForTenant(Tenant tenant) {
        if (tenant == null || tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()) {
            return defaultSchemaName;
        }
        return sanitizeSchemaName(tenant.getSchemaName());
    }

    public String deriveSchemaName(String slug) {
        String base = slug == null || slug.isBlank() ? defaultSchemaName : "tenant_" + slug.trim().toLowerCase();
        return sanitizeSchemaName(base);
    }

    public void ensureSchemaExists(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (provisionedSchemas.contains(normalized)) {
            return;
        }
        Object lock = schemaProvisionLocks.computeIfAbsent(normalized, ignored -> new Object());
        synchronized (lock) {
            if (provisionedSchemas.contains(normalized)) {
                return;
            }
            platformJdbcTemplate.execute("CREATE SCHEMA IF NOT EXISTS " + quotedIdentifier(normalized));
            provisionTenantSchema(normalized);
            provisionedSchemas.add(normalized);
        }
    }

    public void resetTenantSchema(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized) || "platform".equals(normalized)) {
            return;
        }
        dropTenantSchema(normalized);
        ensureSchemaExists(normalized);
    }

    public void dropTenantSchema(String schemaName) {
        String normalized = sanitizeSchemaName(schemaName);
        if (defaultSchemaName.equals(normalized) || "platform".equals(normalized)) {
            return;
        }
        platformJdbcTemplate.execute("DROP SCHEMA IF EXISTS " + quotedIdentifier(normalized) + " CASCADE");
        provisionedSchemas.remove(normalized);
    }

    private String sanitizeSchemaName(String schemaName) {
        String normalized = schemaName == null || schemaName.isBlank() ? defaultSchemaName : schemaName.trim().toLowerCase();
        normalized = normalized.replaceAll("[^a-z0-9_]+", "_");
        normalized = normalized.replaceAll("^[^a-z]+", "tenant_");
        return normalized;
    }

    private void provisionTenantSchema(String targetSchema) {
        if (defaultSchemaName.equals(targetSchema) || "platform".equals(targetSchema)) {
            return;
        }

        List<String> sourceTables = tenantTableNames(defaultSchemaName);
        if (sourceTables.isEmpty()) {
            return;
        }

        List<SequenceDefinition> sourceSequences = tenantSequenceDefinitions(defaultSchemaName);
        List<ColumnDefaultDefinition> sourceDefaults = columnDefaults(defaultSchemaName);
        List<ForeignKeyDefinition> sourceForeignKeys = foreignKeys(defaultSchemaName);
        Set<String> targetForeignKeyNames = foreignKeys(targetSchema).stream()
                .map(ForeignKeyDefinition::constraintName)
                .collect(Collectors.toSet());

        platformJdbcTemplate.execute((ConnectionCallback<Void>) connection -> {
            try (var searchPath = connection.prepareStatement("SELECT set_config('search_path', ?, FALSE)")) {
                searchPath.setString(1, targetSchema + ",platform");
                searchPath.execute();
            }

            try (var statement = connection.createStatement()) {
                for (String tableName : sourceTables) {
                    statement.execute("""
                            CREATE TABLE IF NOT EXISTS %s.%s
                            (LIKE %s.%s INCLUDING CONSTRAINTS INCLUDING GENERATED INCLUDING IDENTITY INCLUDING INDEXES INCLUDING STORAGE INCLUDING COMMENTS)
                            """.formatted(
                            quotedIdentifier(targetSchema),
                            quotedIdentifier(tableName),
                            quotedIdentifier(defaultSchemaName),
                            quotedIdentifier(tableName)
                    ));
                }

                for (SequenceDefinition sequence : sourceSequences) {
                    statement.execute(createSequenceSql(targetSchema, sequence));
                }

                for (ColumnDefaultDefinition defaultDefinition : sourceDefaults) {
                    statement.execute("""
                            ALTER TABLE %s.%s
                            ALTER COLUMN %s SET DEFAULT %s
                            """.formatted(
                            quotedIdentifier(targetSchema),
                            quotedIdentifier(defaultDefinition.tableName()),
                            quotedIdentifier(defaultDefinition.columnName()),
                            rewrittenDefaultExpression(targetSchema, defaultDefinition.defaultExpression())
                    ));
                }

                for (ForeignKeyDefinition foreignKey : sourceForeignKeys) {
                    if (targetForeignKeyNames.contains(foreignKey.constraintName())) {
                        continue;
                    }
                    statement.execute("""
                            ALTER TABLE %s.%s
                            ADD CONSTRAINT %s %s
                            """.formatted(
                            quotedIdentifier(targetSchema),
                            quotedIdentifier(foreignKey.tableName()),
                            quotedIdentifier(foreignKey.constraintName()),
                            rewriteForeignKeyDefinition(targetSchema, foreignKey.definition())
                    ));
                }
            }
            return null;
        });
    }

    private List<String> tenantTableNames(String schemaName) {
        return platformJdbcTemplate.queryForList("""
                SELECT tablename
                FROM pg_tables
                WHERE schemaname = ?
                  AND tablename <> ?
                ORDER BY tablename
                """, String.class, schemaName, FLYWAY_HISTORY_TABLE);
    }

    private List<SequenceDefinition> tenantSequenceDefinitions(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT sequence_name,
                       data_type,
                       start_value,
                       minimum_value,
                       maximum_value,
                       increment,
                       cycle_option
                FROM information_schema.sequences
                WHERE sequence_schema = ?
                ORDER BY sequence_name
                """, sequenceDefinitionMapper(), schemaName);
    }

    private List<ColumnDefaultDefinition> columnDefaults(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT table_name,
                       column_name,
                       column_default
                FROM information_schema.columns
                WHERE table_schema = ?
                  AND column_default IS NOT NULL
                  AND table_name <> ?
                ORDER BY table_name, ordinal_position
                """, columnDefaultMapper(), schemaName, FLYWAY_HISTORY_TABLE);
    }

    private List<ForeignKeyDefinition> foreignKeys(String schemaName) {
        return platformJdbcTemplate.query("""
                SELECT rel.relname AS table_name,
                       con.conname AS constraint_name,
                       pg_get_constraintdef(con.oid) AS definition
                FROM pg_constraint con
                JOIN pg_class rel ON rel.oid = con.conrelid
                JOIN pg_namespace nsp ON nsp.oid = rel.relnamespace
                WHERE nsp.nspname = ?
                  AND con.contype = 'f'
                ORDER BY rel.relname, con.conname
                """, foreignKeyMapper(), schemaName);
    }

    private RowMapper<SequenceDefinition> sequenceDefinitionMapper() {
        return (resultSet, rowNum) -> new SequenceDefinition(
                resultSet.getString("sequence_name"),
                resultSet.getString("data_type"),
                resultSet.getString("start_value"),
                resultSet.getString("minimum_value"),
                resultSet.getString("maximum_value"),
                resultSet.getString("increment"),
                "YES".equalsIgnoreCase(resultSet.getString("cycle_option"))
        );
    }

    private RowMapper<ColumnDefaultDefinition> columnDefaultMapper() {
        return (resultSet, rowNum) -> new ColumnDefaultDefinition(
                resultSet.getString("table_name"),
                resultSet.getString("column_name"),
                resultSet.getString("column_default")
        );
    }

    private RowMapper<ForeignKeyDefinition> foreignKeyMapper() {
        return (resultSet, rowNum) -> new ForeignKeyDefinition(
                resultSet.getString("table_name"),
                resultSet.getString("constraint_name"),
                resultSet.getString("definition")
        );
    }

    private String createSequenceSql(String targetSchema, SequenceDefinition definition) {
        return """
                CREATE SEQUENCE IF NOT EXISTS %s.%s
                AS %s
                INCREMENT BY %s
                MINVALUE %s
                MAXVALUE %s
                START WITH %s
                %s
                """.formatted(
                quotedIdentifier(targetSchema),
                quotedIdentifier(definition.sequenceName()),
                definition.dataType(),
                definition.incrementBy(),
                definition.minValue(),
                definition.maxValue(),
                definition.startValue(),
                definition.cycle() ? "CYCLE" : "NO CYCLE"
        );
    }

    private String rewrittenDefaultExpression(String targetSchema, String expression) {
        return expression.replace(defaultSchemaName + ".", targetSchema + ".");
    }

    private String rewriteForeignKeyDefinition(String targetSchema, String definition) {
        if (defaultSchemaName.equals(targetSchema)) {
            return definition;
        }
        return definition
                .replace("REFERENCES " + defaultSchemaName + ".", "REFERENCES " + targetSchema + ".")
                .replace("REFERENCES " + quotedIdentifier(defaultSchemaName) + ".",
                        "REFERENCES " + quotedIdentifier(targetSchema) + ".");
    }

    private String quotedIdentifier(String value) {
        return "\"" + value.replace("\"", "\"\"") + "\"";
    }

    private record SequenceDefinition(
            String sequenceName,
            String dataType,
            String startValue,
            String minValue,
            String maxValue,
            String incrementBy,
            boolean cycle
    ) {
    }

    private record ColumnDefaultDefinition(String tableName, String columnName, String defaultExpression) {
    }

    private record ForeignKeyDefinition(String tableName, String constraintName, String definition) {
    }
}
