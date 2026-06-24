package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.time.Duration;
import org.springframework.core.task.TaskDecorator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.web.client.RestTemplate;

@Configuration
public class HttpClientConfig {

    @Bean
    public RestTemplate restTemplate(
            RestTemplateBuilder builder,
            @Value("${app.http.connect-timeout-ms:5000}") long connectTimeoutMs,
            @Value("${app.http.read-timeout-ms:30000}") long readTimeoutMs
    ) {
        return builder
                .setConnectTimeout(Duration.ofMillis(connectTimeoutMs))
                .setReadTimeout(Duration.ofMillis(readTimeoutMs))
                .build();
    }

    @Bean
    public OutboundPolicyDefaults outboundPolicyDefaults(
            @Value("${app.http.outbound.min-request-interval-ms:0}") long minRequestIntervalMs,
            @Value("${app.http.outbound.max-retries:3}") int maxRetries,
            @Value("${app.http.outbound.retry-base-backoff-ms:500}") long retryBaseBackoffMs,
            @Value("${app.http.outbound.max-backoff-ms:60000}") long maxBackoffMs,
            @Value("${app.http.outbound.honor-retry-after:true}") boolean honorRetryAfter,
            @Value("${app.http.outbound.retry-on-network-errors:true}") boolean retryOnNetworkErrors
    ) {
        return new OutboundPolicyDefaults(
                minRequestIntervalMs,
                maxRetries,
                retryBaseBackoffMs,
                maxBackoffMs,
                honorRetryAfter,
                retryOnNetworkErrors
        );
    }

    @Bean
    public OutboundPolicyFactory outboundPolicyFactory(OutboundPolicyDefaults outboundPolicyDefaults) {
        return new OutboundPolicyFactory(outboundPolicyDefaults);
    }

    @Bean
    public OutboundHttpClient outboundHttpClient(RestTemplate restTemplate) {
        return new OutboundHttpClient(restTemplate);
    }

    @Bean(name = {"ingestionExecutor", "sbomJobExecutor"})
    public ThreadPoolTaskExecutor ingestionExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(50);
        executor.setThreadNamePrefix("sbom-job-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        executor.initialize();
        return executor;
    }

    @Bean(name = {"integrationQueueExecutor", "feedSyncExecutor"})
    public ThreadPoolTaskExecutor integrationQueueExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(1);
        executor.setMaxPoolSize(1);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("integration-queue-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        executor.initialize();
        return executor;
    }

    @Bean(name = "connectorSyncExecutor")
    public ThreadPoolTaskExecutor connectorSyncExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(2);
        executor.setMaxPoolSize(4);
        executor.setQueueCapacity(100);
        executor.setThreadNamePrefix("connector-sync-");
        executor.setTaskDecorator(tenantContextTaskDecorator());
        executor.initialize();
        return executor;
    }

    static TaskDecorator tenantContextTaskDecorator() {
        return runnable -> {
            TenantContext.Snapshot captured = TenantContext.capture();
            return () -> {
                TenantContext.Snapshot previous = TenantContext.capture();
                try {
                    TenantContext.restore(captured);
                    runnable.run();
                } finally {
                    TenantContext.restore(previous);
                }
            };
        };
    }
}
