package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AuditEvent;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AuditEventRepository extends JpaRepository<AuditEvent, UUID> {
    List<AuditEvent> findTop100ByTenantIdOrderByOccurredAtDesc(UUID tenantId);

    List<AuditEvent> findByTenantIdOrderByOccurredAtDesc(UUID tenantId);

    long countByTenant_IdAndActionAndOccurredAtAfter(UUID tenantId, String action, Instant occurredAt);

    List<AuditEvent> findByTargetTypeAndTargetIdInAndActionInOrderByOccurredAtDesc(
            String targetType,
            List<String> targetIds,
            List<String> actions
    );

    List<AuditEvent> findByTenantIsNullAndTargetTypeAndActionInOrderByOccurredAtDesc(
            String targetType,
            List<String> actions
    );
}
