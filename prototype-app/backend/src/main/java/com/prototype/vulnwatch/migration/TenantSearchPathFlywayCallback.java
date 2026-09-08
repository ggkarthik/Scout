package com.prototype.vulnwatch.migration;

import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;
import org.flywaydb.core.api.callback.BaseCallback;
import org.flywaydb.core.api.callback.Context;
import org.flywaydb.core.api.callback.Event;

/** Ensures unqualified statements in tenant migrations use the tenant schema on every Flyway connection. */
public final class TenantSearchPathFlywayCallback extends BaseCallback {

    private static final Pattern SAFE_SCHEMA_NAME = Pattern.compile("[a-z][a-z0-9_]*");
    private final String schemaName;

    public TenantSearchPathFlywayCallback(String schemaName) {
        if (schemaName == null || !SAFE_SCHEMA_NAME.matcher(schemaName).matches()) {
            throw new IllegalArgumentException("Invalid tenant schema name");
        }
        this.schemaName = schemaName;
    }

    @Override
    public boolean supports(Event event, Context context) {
        return event == Event.BEFORE_EACH_MIGRATE;
    }

    @Override
    public void handle(Event event, Context context) {
        try (Statement statement = context.getConnection().createStatement()) {
            statement.execute("SET search_path TO \"" + schemaName + "\", public");
        } catch (SQLException exception) {
            throw new IllegalStateException("Unable to select tenant schema for Flyway migration", exception);
        }
    }
}
