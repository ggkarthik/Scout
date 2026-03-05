package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CpeDim;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CpeDimRepository extends JpaRepository<CpeDim, UUID> {
    Optional<CpeDim> findByNormalizedCpe(String normalizedCpe);
}
