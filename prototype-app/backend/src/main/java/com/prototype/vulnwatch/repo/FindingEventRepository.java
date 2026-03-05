package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FindingEventRepository extends JpaRepository<FindingEvent, UUID> {
    List<FindingEvent> findByFindingOrderByCreatedAtAsc(Finding finding);

    @Query("""
            select fe
            from FindingEvent fe
            join fe.finding f
            where f.tenant = :tenant
              and fe.eventType = :eventType
              and fe.createdAt >= :fromInclusive
            """)
    List<FindingEvent> findByTenantAndEventTypeSince(
            @Param("tenant") Tenant tenant,
            @Param("eventType") String eventType,
            @Param("fromInclusive") Instant fromInclusive
    );
}
