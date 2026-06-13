package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import org.springframework.jdbc.datasource.DelegatingDataSource;

/**
 * BLG-007: DataSource decorator that sets the PostgreSQL session variable
 * app.current_tenant_id on every connection acquired from the underlying pool,
 * and resets it when the connection is returned (on close()).
 *
 * This allows PostgreSQL Row-Level Security policies to enforce tenant isolation
 * at the database layer, complementing application-layer tenant filtering.
 *
 * set_config(name, value, FALSE) sets a session-level variable that persists for
 * the life of the connection. The reset on close() restores it to an empty string,
 * which the RLS policies treat as "no tenant constraint" in local/dev mode.
 * In production mode, missing tenant context is converted to a sentinel UUID
 * so tenant-scoped RLS policies match no tenant rows.
 */
public class TenantAwareDataSource extends DelegatingDataSource {

    private static final String NO_TENANT_SENTINEL = "00000000-0000-0000-0000-000000000000";

    private final boolean requireTenantContext;
    private final String defaultTenantSchema;

    public TenantAwareDataSource(
            javax.sql.DataSource targetDataSource,
            boolean requireTenantContext,
            String defaultTenantSchema
    ) {
        super(targetDataSource);
        this.requireTenantContext = requireTenantContext;
        this.defaultTenantSchema = defaultTenantSchema;
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection conn = super.getConnection();
        applyTenantContext(conn);
        return wrapWithReset(conn);
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        Connection conn = super.getConnection(username, password);
        applyTenantContext(conn);
        return wrapWithReset(conn);
    }

    private void applyTenantContext(Connection conn) throws SQLException {
        UUID tenantId = TenantContext.getCurrentTenantId();
        String schemaName = normalizeSchemaName(TenantContext.getCurrentSchemaName());
        String value = tenantId != null ? tenantId.toString() : requireTenantContext ? NO_TENANT_SENTINEL : "";
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT set_config('app.current_tenant_id', ?, FALSE)")) {
            ps.setString(1, value);
            ps.execute();
        }
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT set_config('search_path', ?, FALSE)")) {
            ps.setString(1, schemaName + ",platform");
            ps.execute();
        }
    }

    /**
     * Wraps the connection in a JDK proxy that resets app.current_tenant_id before
     * close(), ensuring the pool connection is clean for the next request.
     * ConnectionWrapper was removed in Spring 6; Proxy is the portable alternative.
     */
    private Connection wrapWithReset(Connection target) {
        return (Connection) Proxy.newProxyInstance(
                target.getClass().getClassLoader(),
                new Class[]{Connection.class},
                (proxy, method, args) -> {
                    if ("close".equals(method.getName())) {
                        try (Statement stmt = target.createStatement()) {
                            stmt.execute("RESET app.current_tenant_id");
                            stmt.execute("RESET search_path");
                        } catch (SQLException ignored) {
                            // Best-effort: connection still returned to pool.
                        }
                    }
                    return method.invoke(target, args);
                });
    }

    private String normalizeSchemaName(String schemaName) {
        if (schemaName == null || schemaName.isBlank()) {
            return defaultTenantSchema;
        }
        String normalized = schemaName.trim();
        int separator = normalized.indexOf(',');
        if (separator >= 0) {
            normalized = normalized.substring(0, separator).trim();
        }
        normalized = normalized.toLowerCase();
        normalized = normalized.replaceAll("[^a-z0-9_]+", "_");
        normalized = normalized.replaceAll("^[^a-z]+", "tenant_");
        return normalized.isBlank() ? defaultTenantSchema : normalized;
    }
}
