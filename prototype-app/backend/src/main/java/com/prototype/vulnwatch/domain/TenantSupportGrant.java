package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        schema = "platform",
        name = "tenant_support_grants",
        indexes = {
                @Index(name = "idx_tenant_support_grants_tenant_requested", columnList = "tenant_id,requested_at"),
                @Index(name = "idx_tenant_support_grants_subject_status_expires", columnList = "invited_platform_subject,status,expires_at")
        }
)
public class TenantSupportGrant {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @Column(name = "invited_platform_subject", nullable = false, length = 320)
    private String invitedPlatformSubject;

    @Column(nullable = false, length = 2000)
    private String reason;

    @Column(length = 512)
    private String scope;

    @Column(name = "access_mode", nullable = false, length = 32)
    private String accessMode = "READ_ONLY";

    @Column(nullable = false, length = 32)
    private String status = "PENDING";

    @ManyToOne(optional = false)
    @JoinColumn(name = "granted_by", nullable = false)
    private AppUser grantedBy;

    @ManyToOne
    @JoinColumn(name = "accepted_by")
    private AppUser acceptedBy;

    @ManyToOne
    @JoinColumn(name = "revoked_by")
    private AppUser revokedBy;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt = Instant.now();

    @Column(name = "accepted_at")
    private Instant acceptedAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public String getInvitedPlatformSubject() {
        return invitedPlatformSubject;
    }

    public void setInvitedPlatformSubject(String invitedPlatformSubject) {
        this.invitedPlatformSubject = invitedPlatformSubject;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getAccessMode() {
        return accessMode;
    }

    public void setAccessMode(String accessMode) {
        this.accessMode = accessMode;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public AppUser getGrantedBy() {
        return grantedBy;
    }

    public void setGrantedBy(AppUser grantedBy) {
        this.grantedBy = grantedBy;
    }

    public AppUser getAcceptedBy() {
        return acceptedBy;
    }

    public void setAcceptedBy(AppUser acceptedBy) {
        this.acceptedBy = acceptedBy;
    }

    public AppUser getRevokedBy() {
        return revokedBy;
    }

    public void setRevokedBy(AppUser revokedBy) {
        this.revokedBy = revokedBy;
    }

    public Instant getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(Instant requestedAt) {
        this.requestedAt = requestedAt;
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    public void setAcceptedAt(Instant acceptedAt) {
        this.acceptedAt = acceptedAt;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(Instant revokedAt) {
        this.revokedAt = revokedAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
