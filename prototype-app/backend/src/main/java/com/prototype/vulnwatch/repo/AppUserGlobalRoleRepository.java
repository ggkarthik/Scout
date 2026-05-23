package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AppUserGlobalRole;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserGlobalRoleRepository extends JpaRepository<AppUserGlobalRole, UUID> {
    List<AppUserGlobalRole> findByUser_IdIn(Collection<UUID> userIds);
    List<AppUserGlobalRole> findByRoleOrderByCreatedAtAsc(String role);
    List<AppUserGlobalRole> findByUser_IdOrderByCreatedAtAsc(UUID userId);
    Optional<AppUserGlobalRole> findByUser_IdAndRole(UUID userId, String role);
    void deleteByUser_IdAndRole(UUID userId, String role);
}
