package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Locale;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DemoDatasetProvisioningService {

    private static final Logger LOG = LoggerFactory.getLogger(DemoDatasetProvisioningService.class);

    private final TenantRepository tenantRepository;
    private final JdbcTemplate jdbcTemplate;
    private final CustomerDemoDatasetService datasetService;

    public DemoDatasetProvisioningService(
            TenantRepository tenantRepository,
            JdbcTemplate jdbcTemplate,
            CustomerDemoDatasetService datasetService
    ) {
        this.tenantRepository = tenantRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.datasetService = datasetService;
    }

    @Transactional
    public Tenant request(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenant.setDemoDataRequested(true);
        tenant.setDemoDataStatus("REQUESTED");
        tenant.setDemoDataError(null);
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }

    public CustomerDemoDatasetService.DemoDatasetSummary requestAndSeed(UUID tenantId) {
        request(tenantId);
        return seedIfReady(tenantId);
    }

    @Scheduled(initialDelayString = "${app.demo-data.initial-delay-ms:15000}",
            fixedDelayString = "${app.demo-data.poll-delay-ms:30000}")
    public void seedRequestedTenants() {
        tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                .filter(Tenant::isDemoDataRequested)
                .filter(tenant -> "ACTIVE".equalsIgnoreCase(tenant.getStatus()))
                .filter(tenant -> "REQUESTED".equalsIgnoreCase(tenant.getDemoDataStatus())
                        || "FAILED".equalsIgnoreCase(tenant.getDemoDataStatus()))
                .forEach(tenant -> {
                    try {
                        seedIfReady(tenant.getId());
                    } catch (RuntimeException ex) {
                        LOG.error("Demo dataset seed failed for tenant {}", tenant.getId(), ex);
                    }
                });
    }

    public CustomerDemoDatasetService.DemoDatasetSummary seedIfReady(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalStateException("Tenant must be ACTIVE before demo data can be seeded");
        }
        int claimed = jdbcTemplate.update("""
                UPDATE platform.tenants
                   SET demo_data_requested = true,
                       demo_data_status = 'SEEDING',
                       demo_data_error = null,
                       updated_at = now()
                 WHERE id = ?
                   AND demo_data_status <> 'SEEDING'
                """, tenantId);
        if (claimed == 0) {
            throw new IllegalStateException("Demo data seed is already running");
        }
        try {
            CustomerDemoDatasetService.DemoDatasetSummary summary = datasetService.seed(tenant);
            jdbcTemplate.update("""
                    UPDATE platform.tenants
                       SET demo_data_status = 'SEEDED',
                           demo_data_version = ?,
                           demo_data_seeded_at = now(),
                           demo_data_error = null,
                           updated_at = now()
                     WHERE id = ?
                    """, CustomerDemoDatasetService.DATASET_VERSION, tenantId);
            return summary;
        } catch (RuntimeException ex) {
            String message = rootMessage(ex);
            jdbcTemplate.update("""
                    UPDATE platform.tenants
                       SET demo_data_status = 'FAILED',
                           demo_data_error = ?,
                           updated_at = now()
                     WHERE id = ?
                    """, message.substring(0, Math.min(message.length(), 2000)), tenantId);
            throw ex;
        }
    }

    private String rootMessage(Throwable throwable) {
        Throwable current = throwable;
        while (current.getCause() != null) {
            current = current.getCause();
        }
        String message = current.getMessage();
        return message == null || message.isBlank()
                ? current.getClass().getSimpleName().toLowerCase(Locale.ROOT)
                : message;
    }
}
