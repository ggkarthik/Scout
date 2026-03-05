package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingComment;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingCommentRepository extends JpaRepository<FindingComment, UUID> {
    List<FindingComment> findByFindingOrderByCreatedAtAsc(Finding finding);
}
