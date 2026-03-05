package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SoftwareModel;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SoftwareModelRepository extends JpaRepository<SoftwareModel, UUID> {
    Optional<SoftwareModel> findByNormalizedKey(String normalizedKey);
}
