package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class BackgroundTaskExecutionPolicyTest {

    @Test
    void defaultsUnknownAndBlankRolesToAll() {
        assertThat(new BackgroundTaskExecutionPolicy(null).runtimeRole()).isEqualTo("all");
        assertThat(new BackgroundTaskExecutionPolicy("   ").runtimeRole()).isEqualTo("all");
        assertThat(new BackgroundTaskExecutionPolicy("unexpected").runtimeRole()).isEqualTo("all");
    }

    @Test
    void blocksBackgroundTasksForApiAndSchemaMigratorRoles() {
        assertThat(BackgroundTaskExecutionPolicy.forRole("api").allowsBackgroundTask("queue.poll")).isFalse();
        assertThat(BackgroundTaskExecutionPolicy.forRole("schema-migrator").allowsBackgroundTask("queue.poll"))
                .isFalse();
        assertThat(BackgroundTaskExecutionPolicy.forRole("worker").allowsBackgroundTask("queue.poll")).isTrue();
        assertThat(BackgroundTaskExecutionPolicy.allowAll().allowsBackgroundTask("queue.poll")).isTrue();
    }
}
