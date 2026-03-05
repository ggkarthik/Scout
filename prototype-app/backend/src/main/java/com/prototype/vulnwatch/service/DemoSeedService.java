package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.AdvisoryRequest;
import com.prototype.vulnwatch.dto.AdvisoryRuleRequest;
import com.prototype.vulnwatch.dto.IngestionResult;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class DemoSeedService {

    private final VulnerabilityIngestionService vulnerabilityIngestionService;

    public DemoSeedService(VulnerabilityIngestionService vulnerabilityIngestionService) {
        this.vulnerabilityIngestionService = vulnerabilityIngestionService;
    }

    public IngestionResult seedAdvisories() {
        AdvisoryBatchRequest batch = new AdvisoryBatchRequest(List.of(
                new AdvisoryRequest(
                        "ADV-DEMO-001",
                        "Demo Log4j Advisory",
                        "Remote code execution in log4j demo package",
                        9.8,
                        "CRITICAL",
                        List.of(new AdvisoryRuleRequest(
                                "maven",
                                "log4j-core",
                                null,
                                "2.0.0",
                                "2.17.1",
                                null,
                                "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                        ))
                ),
                new AdvisoryRequest(
                        "ADV-DEMO-002",
                        "Demo Requests Advisory",
                        "Certificate validation bypass in requests demo range",
                        7.5,
                        "HIGH",
                        List.of(new AdvisoryRuleRequest(
                                "pypi",
                                "requests",
                                null,
                                "2.0.0",
                                "2.31.0",
                                null,
                                "cpe:2.3:a:python-requests_project:requests:2.25.0:*:*:*:*:*:*:*"
                        ))
                ),
                new AdvisoryRequest(
                        "ADV-DEMO-003",
                        "Demo Lodash Advisory",
                        "Prototype pollution demo range",
                        8.2,
                        "HIGH",
                        List.of(new AdvisoryRuleRequest(
                                "npm",
                                "lodash",
                                null,
                                "4.0.0",
                                "4.17.20",
                                null,
                                "cpe:2.3:a:lodash:lodash:4.17.19:*:*:*:*:*:*:*"
                        ))
                )
        ));

        return vulnerabilityIngestionService.ingestAdvisories(batch);
    }
}
