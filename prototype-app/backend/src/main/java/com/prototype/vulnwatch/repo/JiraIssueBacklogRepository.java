package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.JiraIssueBacklog;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.UUID;

@Repository
public interface JiraIssueBacklogRepository extends JpaRepository<JiraIssueBacklog, UUID> {
}
