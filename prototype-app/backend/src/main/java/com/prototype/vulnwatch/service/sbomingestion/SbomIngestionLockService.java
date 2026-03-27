package com.prototype.vulnwatch.service.sbomingestion;

import com.prototype.vulnwatch.domain.Tenant;
import java.io.IOException;
import java.util.Locale;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.locks.ReentrantLock;
import org.springframework.stereotype.Service;

@Service
public class SbomIngestionLockService {

    private final ConcurrentMap<String, ReentrantLock> ingestionLocks = new ConcurrentHashMap<>();

    public <T> T withAssetLock(Tenant tenant, String assetIdentifier, Callable<T> action) throws IOException {
        String key = lockKey(tenant, assetIdentifier);
        ReentrantLock lock = ingestionLocks.computeIfAbsent(key, ignored -> new ReentrantLock());
        if (!lock.tryLock()) {
            throw new IOException("An SBOM ingestion is already in progress for this asset. Please retry shortly.");
        }
        try {
            return action.call();
        } catch (IOException ioException) {
            throw ioException;
        } catch (RuntimeException runtimeException) {
            throw runtimeException;
        } catch (Exception checkedException) {
            throw new IOException(checkedException);
        } finally {
            lock.unlock();
            ingestionLocks.remove(key, lock);
        }
    }

    private String lockKey(Tenant tenant, String assetIdentifier) {
        return tenant.getId() + ":" + normalize(assetIdentifier);
    }

    private String normalize(String value) {
        return value == null ? "" : value.trim().toLowerCase(Locale.ROOT);
    }
}
