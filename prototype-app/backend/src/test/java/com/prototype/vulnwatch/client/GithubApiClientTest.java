package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertIterableEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class GithubApiClientTest {

    private final RestTemplate restTemplate = new RestTemplate();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final GithubTokenProvider githubTokenProvider = new GithubTokenProvider(Path.of("build/test-github-token-does-not-exist"));
    private final OutboundHttpClient outboundHttpClient = new OutboundHttpClient(restTemplate);
    private final OutboundPolicyFactory outboundPolicyFactory = new OutboundPolicyFactory(
            new OutboundPolicyDefaults(0L, 1, 1L, 60000L, true, true)
    );
    private final GithubApiClient client = new GithubApiClient(
            objectMapper,
            githubTokenProvider,
            outboundHttpClient,
            outboundPolicyFactory
    );
    private MockRestServiceServer server;

    @BeforeEach
    void setUp() {
        server = MockRestServiceServer.createServer(restTemplate);
        ReflectionTestUtils.setField(client, "baseUrl", "https://api.github.com");
        ReflectionTestUtils.setField(client, "allowlistEnabled", false);
        ReflectionTestUtils.setField(githubTokenProvider, "apiToken", "");
        ReflectionTestUtils.setField(githubTokenProvider, "apiTokenFile", "");
        ReflectionTestUtils.setField(client, "allowedReposCsv", "");
        ReflectionTestUtils.setField(client, "allowedPackagesCsv", "");
        ReflectionTestUtils.setField(client, "maxRetries", 1);
        ReflectionTestUtils.setField(client, "retryBaseBackoffMs", 1L);
        ReflectionTestUtils.setField(client, "maxPagesPerCollection", 250);
        ReflectionTestUtils.setField(client, "minRateLimitRemaining", 25);
        client.init();
    }

    @Test
    void fetchAttestedSbom_extractsSpdxPredicateForMatchingDigest() throws Exception {
        String digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
        String imageRepository = "ghcr.io/ggkarthik/p1_service-owner-workspace";
        String statement = """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [
                    {
                      "name": "%s",
                      "digest": {
                        "sha256": "%s"
                      }
                    }
                  ],
                  "predicateType": "https://spdx.dev/Document",
                  "predicate": {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [
                      {
                        "name": "example",
                        "versionInfo": "1.0.0"
                      }
                    ]
                  }
                }
                """.formatted(imageRepository, digest.substring("sha256:".length()));
        String payload = Base64.getEncoder().encodeToString(statement.getBytes(StandardCharsets.UTF_8));
        String responseBody = """
                {
                  "total_count": 1,
                  "attestations": [
                    {
                      "bundle": {
                        "dsseEnvelope": {
                          "payloadType": "application/vnd.in-toto+json",
                          "payload": "%s",
                          "signatures": []
                        }
                      }
                    }
                  ]
                }
                """.formatted(payload);

        server.expect(requestTo(client.buildAttestationsEndpoint(
                        "ggkarthik",
                        "p1_service-owner-workspace",
                        digest)))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(responseBody, MediaType.APPLICATION_JSON));

        GithubApiClient.GithubAttestedSbomResponse response = client.fetchAttestedSbom(
                "ggkarthik",
                "p1_service-owner-workspace",
                digest,
                imageRepository);

        assertEquals("https://spdx.dev/Document", response.predicateType());
        assertEquals(imageRepository, response.subjectName());
        assertEquals(1, response.attestationCount());
        assertEquals(
                "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[{\"name\":\"example\",\"versionInfo\":\"1.0.0\"}]}",
                new String(response.payload(), StandardCharsets.UTF_8));
        server.verify();
    }

    @Test
    void fetchAttestedSbom_rejectsBundlesWithoutMatchingDigest() {
        String digest = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
        String statement = """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [
                    {
                      "name": "ghcr.io/ggkarthik/p1_service-owner-workspace",
                      "digest": {
                        "sha256": "3333333333333333333333333333333333333333333333333333333333333333"
                      }
                    }
                  ],
                  "predicateType": "https://spdx.dev/Document",
                  "predicate": {
                    "spdxVersion": "SPDX-2.3"
                  }
                }
                """;
        String payload = Base64.getEncoder().encodeToString(statement.getBytes(StandardCharsets.UTF_8));
        String responseBody = """
                {
                  "attestations": [
                    {
                      "bundle": {
                        "dsseEnvelope": {
                          "payload": "%s"
                        }
                      }
                    }
                  ]
                }
                """.formatted(payload);

        server.expect(requestTo(client.buildAttestationsEndpoint(
                        "ggkarthik",
                        "p1_service-owner-workspace",
                        digest)))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(responseBody, MediaType.APPLICATION_JSON));

        assertThrows(IOException.class, () -> client.fetchAttestedSbom(
                "ggkarthik",
                "p1_service-owner-workspace",
                digest,
                "ghcr.io/ggkarthik/p1_service-owner-workspace"));
        server.verify();
    }

    @Test
    void listContainerPackagesAndVersions_extractsGhcrPackagesDigestsAndTags() throws Exception {
        String owner = "ggkarthik";
        String packageName = "p1_service-owner-workspace";

        server.expect(requestTo("https://api.github.com/orgs/ggkarthik/packages?package_type=container&per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        [
                          {
                            "name": "%s"
                          }
                        ]
                        """.formatted(packageName), MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.github.com/users/ggkarthik/packages?package_type=container&per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.github.com/orgs/ggkarthik/packages/container/p1_service-owner-workspace/versions?per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        [
                          {
                            "name": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                            "metadata": {
                              "container": {
                                "tags": ["latest", "1.0.0"]
                              }
                            }
                          }
                        ]
                        """, MediaType.APPLICATION_JSON));

        List<GithubApiClient.GithubContainerPackageRef> packages = client.listContainerPackages(owner);
        List<GithubApiClient.GithubContainerImageVersionRef> versions = client.listContainerImageVersions(owner, packageName);

        assertEquals(1, packages.size());
        assertEquals("ghcr.io/ggkarthik/p1_service-owner-workspace", packages.get(0).imageRepository());
        assertEquals(1, versions.size());
        assertEquals("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", versions.get(0).digest());
        assertIterableEquals(List.of("1.0.0", "latest"), versions.get(0).tags());
        server.verify();
    }

    @Test
    void fetchAttestedSbomForOwner_fallsBackToUserNamespace() throws Exception {
        String digest = "sha256:4444444444444444444444444444444444444444444444444444444444444444";
        String imageRepository = "ghcr.io/ggkarthik/p1_service-owner-workspace";
        String statement = """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [
                    {
                      "name": "%s",
                      "digest": {
                        "sha256": "%s"
                      }
                    }
                  ],
                  "predicateType": "https://spdx.dev/Document",
                  "predicate": {
                    "spdxVersion": "SPDX-2.3"
                  }
                }
                """.formatted(imageRepository, digest.substring("sha256:".length()));
        String payload = Base64.getEncoder().encodeToString(statement.getBytes(StandardCharsets.UTF_8));

        server.expect(requestTo(client.buildOrgOwnerAttestationsEndpoint("ggkarthik", digest)))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));
        server.expect(requestTo(client.buildUserOwnerAttestationsEndpoint("ggkarthik", digest)))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        {
                          "attestations": [
                            {
                              "bundle": {
                                "dsseEnvelope": {
                                  "payload": "%s"
                                }
                              }
                            }
                          ]
                        }
                        """.formatted(payload), MediaType.APPLICATION_JSON));

        GithubApiClient.GithubAttestedSbomResponse response = client.fetchAttestedSbomForOwner(
                "ggkarthik",
                digest,
                imageRepository);

        assertEquals("https://spdx.dev/Document", response.predicateType());
        assertEquals(imageRepository, response.subjectName());
        server.verify();
    }

    @Test
    void fetchAttestedSbomsForOwnerBulk_matchesDockerAndPurlSubjects() throws Exception {
        String firstDigest = "sha256:5555555555555555555555555555555555555555555555555555555555555555";
        String secondDigest = "sha256:6666666666666666666666666666666666666666666666666666666666666666";
        String firstRepository = "ghcr.io/ggkarthik/payments-main";
        String secondRepository = "ghcr.io/ggkarthik/orders-api";

        String firstStatement = """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [
                    {
                      "name": "docker://%s@%s",
                      "digest": {
                        "sha256": "%s"
                      }
                    }
                  ],
                  "predicateType": "https://spdx.dev/Document",
                  "predicate": {
                    "spdxVersion": "SPDX-2.3",
                    "name": "payments"
                  }
                }
                """.formatted(firstRepository, firstDigest, firstDigest.substring("sha256:".length()));
        String secondStatement = """
                {
                  "_type": "https://in-toto.io/Statement/v1",
                  "subject": [
                    {
                      "name": "pkg:docker/ggkarthik/orders-api@%s?tag=latest",
                      "digest": {
                        "sha256": "%s"
                      }
                    }
                  ],
                  "predicateType": "https://spdx.dev/Document",
                  "predicate": {
                    "spdxVersion": "SPDX-2.3",
                    "name": "orders"
                  }
                }
                """.formatted(secondDigest, secondDigest.substring("sha256:".length()));

        String responseBody = """
                {
                  "attestations": [
                    {
                      "bundle": {
                        "dsseEnvelope": {
                          "payload": "%s"
                        }
                      }
                    },
                    {
                      "bundle": {
                        "dsseEnvelope": {
                          "payload": "%s"
                        }
                      }
                    }
                  ]
                }
                """.formatted(
                Base64.getEncoder().encodeToString(firstStatement.getBytes(StandardCharsets.UTF_8)),
                Base64.getEncoder().encodeToString(secondStatement.getBytes(StandardCharsets.UTF_8)));

        server.expect(requestTo(client.buildOrgOwnerBulkAttestationsEndpoint("ggkarthik")))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().json("""
                        {
                          "subject_digests": [
                            "%s",
                            "%s"
                          ],
                          "predicate_type": "sbom"
                        }
                        """.formatted(firstDigest, secondDigest)))
                .andRespond(withSuccess(responseBody, MediaType.APPLICATION_JSON));

        Map<String, GithubApiClient.GithubAttestedSbomResponse> responses = client.fetchAttestedSbomsForOwnerBulk(
                "ggkarthik",
                List.of(
                        new GithubApiClient.GithubAttestationLookup(firstRepository, firstDigest),
                        new GithubApiClient.GithubAttestationLookup(secondRepository, secondDigest)));

        assertEquals(2, responses.size());
        assertEquals("docker://ghcr.io/ggkarthik/payments-main@sha256:5555555555555555555555555555555555555555555555555555555555555555",
                responses.get(firstRepository + "@" + firstDigest).subjectName());
        assertEquals("pkg:docker/ggkarthik/orders-api@sha256:6666666666666666666666666666666666666666666666666666666666666666?tag=latest",
                responses.get(secondRepository + "@" + secondDigest).subjectName());
        server.verify();
    }

    @Test
    void listContainerPackages_usesDedicatedPackageAllowlist() throws Exception {
        ReflectionTestUtils.setField(client, "allowlistEnabled", true);
        ReflectionTestUtils.setField(client, "allowedReposCsv", "ggkarthik/other-repo");
        ReflectionTestUtils.setField(client, "allowedPackagesCsv", "ggkarthik/payments-main");
        client.init();

        server.expect(requestTo("https://api.github.com/orgs/ggkarthik/packages?package_type=container&per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("""
                        [
                          { "name": "payments-main" },
                          { "name": "orders-api" }
                        ]
                        """, MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://api.github.com/users/ggkarthik/packages?package_type=container&per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess("[]", MediaType.APPLICATION_JSON));

        List<GithubApiClient.GithubContainerPackageRef> packages = client.listContainerPackages("ggkarthik");

        assertEquals(1, packages.size());
        assertEquals("ghcr.io/ggkarthik/payments-main", packages.get(0).imageRepository());
        server.verify();
    }

    @Test
    void listContainerPackages_stopsWhenRateLimitIsNearlyExhausted() {
        ReflectionTestUtils.setField(client, "minRateLimitRemaining", 5);
        client.init();
        StringBuilder pageBody = new StringBuilder("[");
        for (int i = 0; i < 100; i++) {
            if (i > 0) {
                pageBody.append(',');
            }
            pageBody.append("{\"name\":\"pkg-").append(i).append("\"}");
        }
        pageBody.append(']');

        server.expect(requestTo("https://api.github.com/orgs/ggkarthik/packages?package_type=container&per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withSuccess(pageBody.toString(), MediaType.APPLICATION_JSON)
                        .header("X-RateLimit-Remaining", "4"));

        IOException error = assertThrows(IOException.class, () -> client.listContainerPackages("ggkarthik"));

        assertEquals("GitHub packages API paused because the GitHub API rate limit is nearly exhausted (remaining: 4)",
                error.getMessage());
        server.verify();
    }

    @Test
    void listContainerPackagesPreservesAuthorizationErrorMapping() {
        server.expect(requestTo("https://api.github.com/orgs/ggkarthik/packages?package_type=container&per_page=100&page=1"))
                .andExpect(method(HttpMethod.GET))
                .andRespond(withStatus(HttpStatus.FORBIDDEN));

        IOException error = assertThrows(IOException.class, () -> client.listContainerPackages("ggkarthik"));

        assertEquals(
                "GitHub packages API request failed with status 403. GHCR discovery requires a GitHub token with at least read:packages access. "
                        + githubTokenProvider.configurationHint(),
                error.getMessage()
        );
        server.verify();
    }
}
