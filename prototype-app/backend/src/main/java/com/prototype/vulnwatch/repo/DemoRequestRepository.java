package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.DemoRequest;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DemoRequestRepository extends JpaRepository<DemoRequest, UUID> {
    List<DemoRequest> findAllByOrderByRequestedAtDesc();
    Optional<DemoRequest> findFirstByEmailIgnoreCaseAndStatusInOrderByRequestedAtDesc(String email, List<String> statuses);
}
