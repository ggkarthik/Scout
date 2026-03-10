package com.prototype.vulnwatch.support;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public final class LocalPostgresTestDatabase {

    public record DatabaseConfig(String url, String username, String password) {
    }

    private static final String DEFAULT_ADMIN_URL = "jdbc:postgresql://localhost:5432/postgres";
    private static final Map<String, DatabaseConfig> DATABASES = new ConcurrentHashMap<>();

    private LocalPostgresTestDatabase() {
    }

    public static DatabaseConfig provision(String key) {
        return DATABASES.computeIfAbsent(key, LocalPostgresTestDatabase::createDatabase);
    }

    private static DatabaseConfig createDatabase(String key) {
        String adminUrl = systemPropertyOrDefault("postgres.test.admin-url", DEFAULT_ADMIN_URL);
        String username = systemPropertyOrDefault("postgres.test.username", System.getProperty("user.name"));
        String password = systemPropertyOrDefault("postgres.test.password", "");
        String databaseName = "vulnwatch_it_" + sanitizeKey(key);

        try (Connection connection = DriverManager.getConnection(adminUrl, username, password);
             Statement statement = connection.createStatement()) {
            statement.execute("DROP DATABASE IF EXISTS " + databaseName + " WITH (FORCE)");
            statement.execute("CREATE DATABASE " + databaseName);
        } catch (SQLException exception) {
            throw new IllegalStateException("Failed to provision local Postgres test database " + databaseName, exception);
        }

        String databaseUrl = adminUrl.replaceFirst("/postgres$", "/" + databaseName);
        return new DatabaseConfig(databaseUrl, username, password);
    }

    private static String systemPropertyOrDefault(String name, String defaultValue) {
        String value = System.getProperty(name);
        if (value == null || value.isBlank()) {
            return defaultValue;
        }
        return value;
    }

    private static String sanitizeKey(String key) {
        String normalized = key == null ? "default" : key.toLowerCase(Locale.ROOT);
        return normalized.replaceAll("[^a-z0-9]+", "_");
    }
}
