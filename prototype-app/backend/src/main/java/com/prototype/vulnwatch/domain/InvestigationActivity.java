package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;

/**
 * Activity log for investigation tracking
 */
@Entity
@Table(name = "investigation_activities")
@Data
@EqualsAndHashCode(of = "id")
public class InvestigationActivity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "investigation_id", nullable = false)
    private Investigation investigation;

    @Column(name = "activity_type", nullable = false, length = 50)
    @Enumerated(EnumType.STRING)
    private ActivityType activityType;

    @Column(name = "description", columnDefinition = "TEXT")
    private String description;

    @Column(name = "performed_by", length = 100)
    private String performedBy;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "metadata", columnDefinition = "TEXT")
    private String metadata;

    public enum ActivityType {
        CREATED,
        STATUS_CHANGED,
        ASSIGNED,
        NOTES_UPDATED,
        ATTACHMENT_ADDED,
        COMMENT_ADDED,
        PRIORITY_CHANGED,
        CLOSED,
        REOPENED
    }
}
