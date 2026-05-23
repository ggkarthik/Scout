package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GithubSbomSource;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface GithubSbomSourceRepository extends JpaRepository<GithubSbomSource, UUID> {
    List<GithubSbomSource> findAllByOrderByCreatedAtAsc();
    List<GithubSbomSource> findByEnabledTrueOrderByCreatedAtAsc();
    List<GithubSbomSource> findByEnabledTrueAndFrequencyIsNotNullOrderByCreatedAtAsc();

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select s from GithubSbomSource s where s.id = :id")
    Optional<GithubSbomSource> findByIdForUpdate(@Param("id") UUID id);

    Optional<GithubSbomSource> findById(UUID id);
}
