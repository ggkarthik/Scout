package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.service.cmdbingestion.CmdbInventoryIngestionRunner;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CmdbIngestionService {

    private final CmdbInventoryIngestionRunner cmdbInventoryIngestionRunner;

    public CmdbIngestionService(CmdbInventoryIngestionRunner cmdbInventoryIngestionRunner) {
        this.cmdbInventoryIngestionRunner = cmdbInventoryIngestionRunner;
    }

    @Transactional
    public CmdbInventorySyncResponse ingestRows(
            Tenant tenant,
            String sourceSystem,
            List<Map<String, String>> installRowValues,
            List<Map<String, String>> discoveryRowValues,
            HostInventorySourceDescriptor sourceDescriptor
    ) {
        return cmdbInventoryIngestionRunner.ingestRows(
                tenant,
                sourceSystem,
                installRowValues,
                discoveryRowValues,
                sourceDescriptor
        );
    }

    public record HostInventorySourceDescriptor(
            String originalFilename,
            String ingestionSourceType,
            String sourceSystem,
            String sourceReference,
            String sourceEndpoint,
            String contentType,
            Long contentLengthBytes
    ) {
    }
}
