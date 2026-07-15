package com.prototype.vulnwatch.service;

import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Controls whether scheduled and startup background work should execute on the current node.
 *
 * <p>Default role {@code all} preserves current single-node behavior. Deployments that split API
 * and worker responsibilities can set {@code app.runtime.role=api} on interactive nodes to keep
 * schedulers and queue pollers off those instances without changing API contracts or page behavior.
 * The one-shot {@code schema-migrator} role also disables background work so privileged migration
 * credentials are never used by ordinary application jobs.
 */
@Component
public class BackgroundTaskExecutionPolicy {

    private static final Logger LOG = LoggerFactory.getLogger(BackgroundTaskExecutionPolicy.class);

    private final RuntimeRole runtimeRole;
    private final Set<String> loggedSkips = ConcurrentHashMap.newKeySet();

    public BackgroundTaskExecutionPolicy(@Value("${app.runtime.role:all}") String configuredRole) {
        this.runtimeRole = parseRole(configuredRole);
    }

    public static BackgroundTaskExecutionPolicy allowAll() {
        return new BackgroundTaskExecutionPolicy("all");
    }

    public static BackgroundTaskExecutionPolicy forRole(String configuredRole) {
        return new BackgroundTaskExecutionPolicy(configuredRole);
    }

    public boolean allowsBackgroundTask(String taskName) {
        if (runtimeRole != RuntimeRole.API && runtimeRole != RuntimeRole.SCHEMA_MIGRATOR) {
            return true;
        }
        if (loggedSkips.add(taskName)) {
            LOG.info(
                    "Skipping background task {} because app.runtime.role={} disables worker-side schedulers on this node",
                    taskName,
                    runtimeRole.configValue
            );
        }
        return false;
    }

    public String runtimeRole() {
        return runtimeRole.configValue;
    }

    private static RuntimeRole parseRole(String configuredRole) {
        String normalized = configuredRole == null ? "all" : configuredRole.trim().toLowerCase(Locale.ROOT);
        return switch (normalized) {
            case "", "all" -> RuntimeRole.ALL;
            case "api" -> RuntimeRole.API;
            case "worker" -> RuntimeRole.WORKER;
            case "schema-migrator" -> RuntimeRole.SCHEMA_MIGRATOR;
            default -> {
                LOG.warn("Unknown app.runtime.role value '{}' ; defaulting to 'all'", configuredRole);
                yield RuntimeRole.ALL;
            }
        };
    }

    private enum RuntimeRole {
        ALL("all"),
        API("api"),
        WORKER("worker"),
        SCHEMA_MIGRATOR("schema-migrator");

        private final String configValue;

        RuntimeRole(String configValue) {
            this.configValue = configValue;
        }
    }
}
