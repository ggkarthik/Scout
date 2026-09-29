package com.prototype.vulnwatch.service.sbomingestion;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.service.IngestionJobLockService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;

/**
 * Pins down the two Postgres behaviours the per-asset ingestion lock depends on.
 *
 * <p>SbomIngestionLockService now derives its key from {@link IngestionJobLockService}, so a
 * direct upload and a queued ingestion job contend on the same key for the same asset. The
 * ingestion-job worker acquires that key and then calls the orchestrator, whose
 * {@code @Transactional} method joins the worker's transaction -- so the same session asks for
 * a key it already holds. If advisory locks were not re-entrant, every queued BOM fetch would
 * fail with "an SBOM ingestion is already in progress for this asset".
 */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AssetAdvisoryLockPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("asset_advisory_lock");

    private final long assetKey =
            new IngestionJobLockService(new JdbcTemplate())
                    .assetLockKey(UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc"), "pkg:npm/app");

    @Test
    void theSameTransactionMayReacquireTheAssetKey() throws Exception {
        try (Connection connection = connection()) {
            connection.setAutoCommit(false);
            assertTrue(tryLock(connection, assetKey), "first acquisition should succeed");
            assertTrue(tryLock(connection, assetKey),
                    "a transaction that already holds the key must be able to reacquire it, "
                            + "otherwise the job worker calling into the orchestrator deadlocks itself");
            connection.rollback();
        }
    }

    @Test
    void aSecondSessionCannotTakeAHeldAssetKey() throws Exception {
        try (Connection holder = connection()) {
            holder.setAutoCommit(false);
            assertTrue(tryLock(holder, assetKey));

            try (Connection contender = connection()) {
                contender.setAutoCommit(false);
                assertFalse(tryLock(contender, assetKey),
                        "a concurrent ingestion on another instance must fail fast, not interleave");
                contender.rollback();
            }
            holder.rollback();
        }
    }

    @Test
    void endingTheTransactionReleasesTheAssetKeyWithoutAnExplicitUnlock() throws Exception {
        try (Connection holder = connection()) {
            holder.setAutoCommit(false);
            assertTrue(tryLock(holder, assetKey));
            // No unlock call: this is what makes the lock impossible to leak, unlike the
            // in-process lock it replaced, which stranded an asset for the life of the JVM.
            holder.rollback();
        }

        try (Connection next = connection()) {
            next.setAutoCommit(false);
            assertTrue(tryLock(next, assetKey), "the key must be free once the holder's transaction ends");
            next.rollback();
        }
    }

    @Test
    void differentAssetsDoNotContend() throws Exception {
        long otherAsset = new IngestionJobLockService(new JdbcTemplate())
                .assetLockKey(UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc"), "pkg:npm/other");
        try (Connection holder = connection()) {
            holder.setAutoCommit(false);
            assertTrue(tryLock(holder, assetKey));

            try (Connection contender = connection()) {
                contender.setAutoCommit(false);
                assertTrue(tryLock(contender, otherAsset),
                        "ingestion for one asset must not block another");
                contender.rollback();
            }
            holder.rollback();
        }
    }

    private boolean tryLock(Connection connection, long key) throws Exception {
        try (PreparedStatement statement =
                     connection.prepareStatement("select pg_try_advisory_xact_lock(?)")) {
            statement.setLong(1, key);
            try (ResultSet resultSet = statement.executeQuery()) {
                resultSet.next();
                return resultSet.getBoolean(1);
            }
        }
    }

    private Connection connection() throws Exception {
        return DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
    }
}
