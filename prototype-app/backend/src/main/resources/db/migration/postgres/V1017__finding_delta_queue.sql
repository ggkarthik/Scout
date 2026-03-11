-- BLG-006: Durable delta queue — replaces the volatile in-memory ThreadPoolTaskExecutor queue.
-- Events are written transactionally and polled via SELECT FOR UPDATE SKIP LOCKED.

CREATE TABLE IF NOT EXISTS finding_delta_queue (
    id                    bigserial    PRIMARY KEY,
    event_type            varchar(30)  NOT NULL,
    tenant_id             uuid,
    component_id          uuid,
    vulnerability_id      uuid,
    source_key            varchar(500),
    source_tag            varchar(255),
    dedupe_key            varchar(700) NOT NULL,
    status                varchar(20)  NOT NULL DEFAULT 'PENDING',
    attempt_count         int          NOT NULL DEFAULT 0,
    max_attempts          int          NOT NULL DEFAULT 3,
    enqueued_at           timestamptz  NOT NULL DEFAULT now(),
    visible_after         timestamptz  NOT NULL DEFAULT now(),
    processing_started_at timestamptz,
    completed_at          timestamptz,
    error_message         text
);

-- Prevents duplicate PENDING events for the same logical work unit.
-- Multiple DONE/FAILED rows for the same key are allowed (audit trail).
CREATE UNIQUE INDEX IF NOT EXISTS idx_fdq_dedupe_pending
    ON finding_delta_queue (dedupe_key)
    WHERE status = 'PENDING';

-- Used by the scheduled poller: WHERE status='PENDING' AND visible_after<=now() ORDER BY id LIMIT N
CREATE INDEX IF NOT EXISTS idx_fdq_pending_visible
    ON finding_delta_queue (status, visible_after, id)
    WHERE status = 'PENDING';
