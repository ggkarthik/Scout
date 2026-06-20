package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomRiskClass;
import org.junit.jupiter.api.Test;

class CbomRiskEngineTest {

    private final CbomRiskEngine riskEngine = new CbomRiskEngine(new ObjectMapper());

    @Test
    void flagsSmallRsaAsKeyManagementAndQuantumRisk() {
        CbomComponent component = new CbomComponent();
        component.setAssetType(CbomAssetType.ALGORITHM);
        component.setComponentFingerprint("test");
        component.setName("RSA-1024");
        component.setPrimitive("RSA");
        component.setKeySize(1024);

        var findings = riskEngine.evaluate(component);

        assertThat(findings).extracting("riskClass")
                .contains(CbomRiskClass.KEY_MANAGEMENT, CbomRiskClass.QUANTUM_VULNERABLE);
    }

    @Test
    void doesNotFlagModernSymmetricAlgorithm() {
        CbomComponent component = new CbomComponent();
        component.setAssetType(CbomAssetType.ALGORITHM);
        component.setComponentFingerprint("test");
        component.setName("AES-256-GCM");
        component.setPrimitive("AES");
        component.setKeySize(256);

        var findings = riskEngine.evaluate(component);

        assertThat(findings).isEmpty();
    }
}
