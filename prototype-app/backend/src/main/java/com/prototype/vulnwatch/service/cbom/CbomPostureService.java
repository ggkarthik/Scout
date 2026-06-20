package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomPostureSummary;
import com.prototype.vulnwatch.domain.CbomRiskClass;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import com.prototype.vulnwatch.repo.CbomPostureSummaryRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import java.time.Instant;
import java.util.List;
import org.springframework.stereotype.Service;

@Service
public class CbomPostureService {

    private final CbomComponentRepository componentRepository;
    private final CbomRiskFindingRepository findingRepository;
    private final CbomPostureSummaryRepository postureSummaryRepository;
    private final CbomRiskScorer riskScorer;

    public CbomPostureService(
            CbomComponentRepository componentRepository,
            CbomRiskFindingRepository findingRepository,
            CbomPostureSummaryRepository postureSummaryRepository,
            CbomRiskScorer riskScorer
    ) {
        this.componentRepository = componentRepository;
        this.findingRepository = findingRepository;
        this.postureSummaryRepository = postureSummaryRepository;
        this.riskScorer = riskScorer;
    }

    public CbomPostureSummary rollUp(Tenant tenant, Asset asset, BomIngestionRecord sourceBom) {
        List<CbomComponent> components = componentRepository.findByTenant_IdAndAsset_IdAndActiveTrue(tenant.getId(), asset.getId());
        List<CbomRiskFinding> findings = findingRepository.findForAssetAndStatuses(
                tenant.getId(),
                asset.getId(),
                List.of(CbomFindingStatus.OPEN, CbomFindingStatus.ACCEPTED)
        );
        CbomPostureSummary summary = postureSummaryRepository.findByTenant_IdAndAsset_Id(tenant.getId(), asset.getId())
                .orElseGet(CbomPostureSummary::new);
        summary.setTenant(tenant);
        summary.setAsset(asset);
        summary.setLastSourceBom(sourceBom);
        summary.setTotalComponents(components.size());
        summary.setCriticalFindings(countOpenSeverity(findings, CbomRiskSeverity.CRITICAL));
        summary.setHighFindings(countOpenSeverity(findings, CbomRiskSeverity.HIGH));
        summary.setMediumFindings(countOpenSeverity(findings, CbomRiskSeverity.MEDIUM));
        summary.setLowFindings(countOpenSeverity(findings, CbomRiskSeverity.LOW));
        summary.setInfoFindings(countOpenSeverity(findings, CbomRiskSeverity.INFO));
        summary.setAcceptedFindings((int) findings.stream().filter(f -> f.getStatus() == CbomFindingStatus.ACCEPTED).count());
        summary.setQuantumVulnerable(countOpenClass(findings, CbomRiskClass.QUANTUM_VULNERABLE));
        summary.setWeakAlgorithms(countOpenClass(findings, CbomRiskClass.WEAK_ALGORITHM));
        summary.setExpiringCerts(countOpenClass(findings, CbomRiskClass.CERT_EXPIRY));
        summary.setPostureScore(riskScorer.scorePosture(components));
        summary.setLastEvaluatedAt(Instant.now());
        return postureSummaryRepository.save(summary);
    }

    private int countOpenSeverity(List<CbomRiskFinding> findings, CbomRiskSeverity severity) {
        return (int) findings.stream()
                .filter(f -> f.getStatus() == CbomFindingStatus.OPEN)
                .filter(f -> f.getSeverity() == severity)
                .count();
    }

    private int countOpenClass(List<CbomRiskFinding> findings, CbomRiskClass riskClass) {
        return (int) findings.stream()
                .filter(f -> f.getStatus() == CbomFindingStatus.OPEN)
                .filter(f -> f.getRiskClass() == riskClass)
                .count();
    }
}
