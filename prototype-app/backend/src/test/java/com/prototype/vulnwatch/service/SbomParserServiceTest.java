package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.dto.ParsedComponent;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SbomParserServiceTest {

    private final SbomParserService parser = new SbomParserService(new ObjectMapper());

    @Test
    void shouldParseGithubWrappedSpdxSbom() throws Exception {
        String payload = """
                {
                  "sbom": {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [
                      {
                        "name": "lodash",
                        "versionInfo": "4.17.21",
                        "externalRefs": [
                          {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/lodash@4.17.21"
                          }
                        ]
                      }
                    ]
                  }
                }
                """;

        SbomFormat format = parser.detectFormat(payload.getBytes(StandardCharsets.UTF_8));
        List<ParsedComponent> components = parser.parse(payload.getBytes(StandardCharsets.UTF_8));

        Assertions.assertEquals(SbomFormat.SPDX, format);
        Assertions.assertEquals(1, components.size());
        Assertions.assertEquals("npm", components.get(0).ecosystem());
        Assertions.assertEquals("lodash", components.get(0).packageName());
        Assertions.assertEquals("4.17.21", components.get(0).version());
        Assertions.assertTrue(components.get(0).cpes().stream().anyMatch(cpe -> cpe.contains(":lodash:")));
    }

    @Test
    void shouldExtractDigestFromCycloneDxHashes() throws Exception {
        String payload = """
                {
                  "bomFormat": "CycloneDX",
                  "components": [
                    {
                      "name": "requests",
                      "version": "2.31.0",
                      "purl": "pkg:pypi/requests@2.31.0",
                      "hashes": [
                        {
                          "alg": "SHA-256",
                          "content": "4d5f0ca4f0d4f9f95f2f96b3f3f2c12f2f4b6e8f8f4d9a1f8a2c3b4d5e6f7081"
                        }
                      ]
                    }
                  ]
                }
                """;

        List<ParsedComponent> components = parser.parse(payload.getBytes(StandardCharsets.UTF_8));
        Assertions.assertEquals(1, components.size());
        Assertions.assertEquals("sha256:4d5f0ca4f0d4f9f95f2f96b3f3f2c12f2f4b6e8f8f4d9a1f8a2c3b4d5e6f7081", components.get(0).digest());
    }
}
