package com.prototype.vulnwatch.service;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class IngestionJobLockService {

    private final JdbcTemplate jdbcTemplate;

    public IngestionJobLockService(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    public long assetLockKey(UUID tenantId, String normalizedAssetIdentifier) {
        String lockMaterial = (tenantId == null ? "unknown-tenant" : tenantId.toString())
                + ":"
                + (normalizedAssetIdentifier == null ? "" : normalizedAssetIdentifier.trim().toLowerCase());
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(lockMaterial.getBytes(StandardCharsets.UTF_8));
            return ByteBuffer.wrap(digest, 0, Long.BYTES).getLong();
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to derive advisory lock key", ex);
        }
    }

    public boolean tryAcquireTransactionLock(long lockKey) {
        Boolean acquired = jdbcTemplate.queryForObject(
                "select pg_try_advisory_xact_lock(?)",
                Boolean.class,
                lockKey
        );
        return Boolean.TRUE.equals(acquired);
    }
}
