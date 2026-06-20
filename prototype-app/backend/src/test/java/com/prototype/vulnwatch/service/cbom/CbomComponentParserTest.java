package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomAssetType;
import java.nio.charset.StandardCharsets;
import java.time.LocalDate;
import org.junit.jupiter.api.Test;

class CbomComponentParserTest {

    private final CbomComponentParser parser = new CbomComponentParser(new ObjectMapper());

    @Test
    void parsesCycloneDxCryptoPropertiesFromJson() throws Exception {
        String cbom = """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "components": [
                    {
                      "type": "cryptographic-asset",
                      "bom-ref": "crypto:rsa",
                      "name": "RSA signing key",
                      "cryptoProperties": {
                        "assetType": "algorithm",
                        "algorithmProperties": {
                          "primitive": "RSA",
                          "keySize": 1024,
                          "padding": "PKCS1v15"
                        }
                      },
                      "properties": [
                        {"name": "cdx:cbom:sensitivity", "value": "high"},
                        {"name": "cdx:cbom:usedIn", "value": "token signing"}
                      ]
                    },
                    {
                      "type": "cryptographic-asset",
                      "bom-ref": "cert:api",
                      "name": "api.example.com",
                      "cryptoProperties": {
                        "assetType": "certificate",
                        "certificateProperties": {
                          "notAfter": "2026-07-01",
                          "issuer": "Example CA"
                        }
                      }
                    }
                  ]
                }
                """;

        var components = parser.parse(cbom.getBytes(StandardCharsets.UTF_8));

        assertThat(components).hasSize(2);
        assertThat(components.get(0).assetType()).isEqualTo(CbomAssetType.ALGORITHM);
        assertThat(components.get(0).primitive()).isEqualTo("RSA");
        assertThat(components.get(0).keySize()).isEqualTo(1024);
        assertThat(components.get(0).sensitivity()).isEqualTo("high");
        assertThat(components.get(1).assetType()).isEqualTo(CbomAssetType.CERTIFICATE);
        assertThat(components.get(1).notAfter()).isEqualTo(LocalDate.parse("2026-07-01"));
    }
}
