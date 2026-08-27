package com.prototype.vulnwatch.migration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Pattern;

/** Canonical, search-path-independent structural fingerprint for tenant schemas. */
public final class TenantSchemaFingerprint {

    private static final Pattern SCHEMA_NAME = Pattern.compile("[a-z_][a-z0-9_]{0,62}");
    private static final Pattern UUID_VALUE = Pattern.compile(
            "[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}");

    private TenantSchemaFingerprint() {
    }

    public static String of(Connection connection, String schemaName) throws SQLException {
        String normalizedSchema = normalizeSchema(schemaName);
        List<String> definitions = new ArrayList<>();
        String originalSearchPath = currentSearchPath(connection);
        try {
            setSearchPath(connection, "pg_catalog");
            try (PreparedStatement statement = connection.prepareStatement(definitionQuery())) {
                for (int index = 1; index <= 5; index++) {
                    statement.setString(index, normalizedSchema);
                }
                try (ResultSet result = statement.executeQuery()) {
                    while (result.next()) {
                        definitions.add(result.getString(1));
                    }
                }
            }
        } finally {
            setSearchPath(connection, originalSearchPath);
        }

        String normalized = String.join("\n", definitions).replace(normalizedSchema, "<tenant_schema>");
        normalized = UUID_VALUE.matcher(normalized).replaceAll("<tenant_id>");
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(normalized.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to compute tenant schema fingerprint", ex);
        }
    }

    private static String normalizeSchema(String schemaName) {
        String normalized = schemaName == null ? "" : schemaName.trim().toLowerCase(Locale.ROOT);
        if (!SCHEMA_NAME.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Invalid tenant schema name");
        }
        return normalized;
    }

    private static String currentSearchPath(Connection connection) throws SQLException {
        try (Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery("SHOW search_path")) {
            if (!result.next()) {
                throw new SQLException("Unable to read current search_path");
            }
            return result.getString(1);
        }
    }

    private static void setSearchPath(Connection connection, String searchPath) throws SQLException {
        try (PreparedStatement statement = connection.prepareStatement(
                "select set_config('search_path', ?, false)")) {
            statement.setString(1, searchPath);
            statement.execute();
        }
    }

    private static String definitionQuery() {
        return """
                with objects as (
                    select concat_ws('|', 'column', c.table_name, c.ordinal_position::text, c.column_name,
                           c.data_type, coalesce(c.character_maximum_length::text, ''),
                           c.is_nullable, coalesce(c.column_default, ''))::text as definition
                    from information_schema.columns c
                    where c.table_schema = ? and c.table_name not in ('tenant_schema_history', 'flyway_schema_history')
                    union all
                    select concat_ws('|', 'constraint', cl.relname::text, con.contype::text,
                           pg_get_constraintdef(con.oid))::text
                    from pg_constraint con
                    join pg_class cl on cl.oid = con.conrelid
                    join pg_namespace n on n.oid = cl.relnamespace
                    where n.nspname = ?
                    union all
                    select concat_ws('|', 'index', tab.relname::text, idx.relname::text,
                           i.indisunique::text, i.indisprimary::text, i.indkey::text,
                           i.indclass::text, i.indcollation::text, i.indoption::text,
                           regexp_replace(regexp_replace(coalesce(pg_get_expr(i.indexprs, i.indrelid), ''),
                               '::(character varying|text)(\\[\\])?', '', 'g'), '[()[:space:]]', '', 'g'),
                           regexp_replace(regexp_replace(coalesce(pg_get_expr(i.indpred, i.indrelid), ''),
                               '::(character varying|text)(\\[\\])?', '', 'g'), '[()[:space:]]', '', 'g'))::text
                    from pg_index i
                    join pg_class idx on idx.oid = i.indexrelid
                    join pg_class tab on tab.oid = i.indrelid
                    join pg_namespace n on n.oid = tab.relnamespace
                    where n.nspname = ?
                    union all
                    select concat_ws('|', 'sequence', sequence_name, data_type, increment,
                           minimum_value, maximum_value, cycle_option)::text
                    from information_schema.sequences where sequence_schema = ?
                    union all
                    select concat_ws('|', 'rls', c.relname::text, c.relrowsecurity::text,
                           c.relforcerowsecurity::text, coalesce(p.polname::text, ''),
                           coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
                           coalesce(pg_get_expr(p.polwithcheck, p.polrelid), ''))::text
                    from pg_class c
                    join pg_namespace n on n.oid = c.relnamespace
                    left join pg_policy p on p.polrelid = c.oid
                    where n.nspname = ? and c.relkind in ('r', 'p')
                      and c.relname not in ('tenant_schema_history', 'flyway_schema_history')
                )
                select definition from objects order by definition
                """;
    }
}
