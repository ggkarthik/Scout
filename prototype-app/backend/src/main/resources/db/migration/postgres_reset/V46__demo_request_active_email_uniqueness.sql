WITH ranked_active_requests AS (
    SELECT id,
           row_number() OVER (PARTITION BY lower(email) ORDER BY requested_at DESC, id DESC) AS request_rank
    FROM tenant_default.demo_requests
    WHERE status IN ('PENDING', 'SENT', 'ERROR')
)
UPDATE tenant_default.demo_requests request
SET status = 'SUPERSEDED',
    rejection_reason = coalesce(request.rejection_reason, 'Superseded by a newer active request')
FROM ranked_active_requests ranked
WHERE request.id = ranked.id
  AND ranked.request_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uk_demo_requests_active_email
    ON tenant_default.demo_requests (lower(email))
    WHERE status IN ('PENDING', 'SENT', 'ERROR');
