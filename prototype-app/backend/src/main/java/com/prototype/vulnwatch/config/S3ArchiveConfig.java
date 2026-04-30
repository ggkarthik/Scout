package com.prototype.vulnwatch.config;

import java.time.Duration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.http.apache.ApacheHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3ClientBuilder;

@Configuration
@ConditionalOnProperty(prefix = "app.archive", name = "storage-backend", havingValue = "s3")
public class S3ArchiveConfig {

    @Bean
    S3Client archiveS3Client(
            @Value("${app.archive.s3-region:${AWS_REGION:}}") String s3Region,
            @Value("${app.http.connect-timeout-ms:5000}") long connectTimeoutMs,
            @Value("${app.http.read-timeout-ms:30000}") long readTimeoutMs
    ) {
        S3ClientBuilder builder = S3Client.builder()
                .httpClientBuilder(ApacheHttpClient.builder()
                        .connectionTimeout(Duration.ofMillis(connectTimeoutMs))
                        .socketTimeout(Duration.ofMillis(readTimeoutMs)));

        if (s3Region != null && !s3Region.isBlank()) {
            builder.region(Region.of(s3Region.trim()));
        }

        return builder.build();
    }
}
