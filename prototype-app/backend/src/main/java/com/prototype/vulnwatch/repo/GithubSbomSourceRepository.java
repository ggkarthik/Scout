package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GithubSbomSource;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GithubSbomSourceRepository extends JpaRepository<GithubSbomSource, UUID> {
    List<GithubSbomSource> findByEnabledTrueOrderByCreatedAtAsc();
}
