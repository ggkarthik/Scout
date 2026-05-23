package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingEvent;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingEventRepository extends JpaRepository<FindingEvent, UUID> {
    List<FindingEvent> findByFindingOrderByCreatedAtAsc(Finding finding);
    List<FindingEvent> findByEventTypeAndCreatedAtGreaterThanEqual(String eventType, Instant fromInclusive);
}
