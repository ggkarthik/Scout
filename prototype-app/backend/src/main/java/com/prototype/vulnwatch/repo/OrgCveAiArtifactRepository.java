package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.OrgCveAiArtifact;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface OrgCveAiArtifactRepository extends JpaRepository<OrgCveAiArtifact, UUID> {

    Optional<OrgCveAiArtifact> findByOrgCveRecordId(UUID orgCveRecordId);
}
