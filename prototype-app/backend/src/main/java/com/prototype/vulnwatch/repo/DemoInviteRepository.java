package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.DemoInvite;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DemoInviteRepository extends JpaRepository<DemoInvite, UUID> {
    Optional<DemoInvite> findByToken(String token);
    List<DemoInvite> findByRequest_IdOrderByCreatedAtDesc(UUID requestId);
}
