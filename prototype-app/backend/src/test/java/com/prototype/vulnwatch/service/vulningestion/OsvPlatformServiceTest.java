package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OsvApiClient;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvQueryResponse;
import com.prototype.vulnwatch.client.http.OsvApiClient.OsvVulnerability;
import com.prototype.vulnwatch.domain.AdvisoryEquivalenceEntity;
import com.prototype.vulnwatch.domain.OsvAdvisoryEntity;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.repo.AdvisoryEquivalenceRepository;
import com.prototype.vulnwatch.repo.OsvAdvisoryRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class OsvPlatformServiceTest {

  @Mock
  private OsvApiClient osvApiClient;

  @Mock
  private OsvAdvisoryRepository osvAdvisoryRepository;

  @Mock
  private AdvisoryEquivalenceRepository equivalenceRepository;

  @Mock
  private SoftwareIdentityRepository softwareIdentityRepository;

  private OsvPlatformService service;
  private ObjectMapper objectMapper;

  @BeforeEach
  void setUp() {
    objectMapper = new ObjectMapper();
    service = new OsvPlatformService(osvApiClient, osvAdvisoryRepository,
        equivalenceRepository, softwareIdentityRepository);
  }

  @Test
  void testSyncOsvAdvisories_CreatesRecords() {
    SoftwareIdentity identity = new SoftwareIdentity();
    identity.setPurl("pkg:npm/lodash@4.17.20");
    when(softwareIdentityRepository.findAll()).thenReturn(List.of(identity));
    OsvQueryResponse mockResponse = OsvQueryResponse.builder()
        .vulns(Arrays.asList(
            OsvVulnerability.builder()
                .id("GHSA-35jh-r3h4-6jhm")
                .summary("Command Injection")
                .severity(Collections.singletonList(
                    new OsvApiClient.OsvSeverity("CVSS_V3", "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H")
                ))
                .published(java.time.Instant.now())
                .aliases(Arrays.asList("CVE-2021-23337"))
                .build()
        ))
        .build();

    when(osvApiClient.queryByPackageVersion("npm", "lodash", null))
        .thenReturn(mockResponse);

    when(osvAdvisoryRepository.findByOsvId("GHSA-35jh-r3h4-6jhm"))
        .thenReturn(java.util.Optional.empty());

    service.syncOsvAdvisories();

    ArgumentCaptor<OsvAdvisoryEntity> captor = ArgumentCaptor.forClass(OsvAdvisoryEntity.class);
    verify(osvAdvisoryRepository, times(1)).save(captor.capture());

    OsvAdvisoryEntity saved = captor.getValue();
    assertEquals("GHSA-35jh-r3h4-6jhm", saved.getOsvId());
    assertEquals("npm", saved.getEcosystem());
  }

  @Test
  void testBuildEquivalenceMappings_LinksCveAndGhsa() {
    OsvAdvisoryEntity entity = OsvAdvisoryEntity.builder()
        .id(java.util.UUID.randomUUID())
        .osvId("OSV-2021-1234")
        .ecosystem("npm")
        .packageName("lodash")
        .summary("Test")
        .affectedRanges("[]")
        .osvData("{\"id\":\"OSV-2021-1234\",\"aliases\":[\"CVE-2021-23337\",\"GHSA-35jh-r3h4-6jhm\"]}")
        .source("nvd")
        .build();

    when(osvAdvisoryRepository.findAll())
        .thenReturn(Arrays.asList(entity));

    when(equivalenceRepository.existsByNvdCveIdAndGhsaIdAndOsvId("CVE-2021-23337", "GHSA-35jh-r3h4-6jhm", "OSV-2021-1234"))
        .thenReturn(false);

    service.buildEquivalenceMappings();

    ArgumentCaptor<AdvisoryEquivalenceEntity> captor = ArgumentCaptor.forClass(AdvisoryEquivalenceEntity.class);
    verify(equivalenceRepository, times(1)).save(captor.capture());

    AdvisoryEquivalenceEntity eq = captor.getValue();
    assertEquals("CVE-2021-23337", eq.getNvdCveId());
    assertEquals("GHSA-35jh-r3h4-6jhm", eq.getGhsaId());
    assertEquals("OSV-2021-1234", eq.getOsvId());
  }

  @Test
  void testSaveOsvAdvisory_SkipsDuplicates() {
    SoftwareIdentity identity = new SoftwareIdentity();
    identity.setPurl("pkg:npm/lodash@4.17.20");
    when(softwareIdentityRepository.findAll()).thenReturn(List.of(identity));
    OsvVulnerability vuln = OsvVulnerability.builder()
        .id("GHSA-35jh-r3h4-6jhm")
        .summary("Test")
        .build();

    when(osvApiClient.queryByPackageVersion("npm", "lodash", null))
        .thenReturn(OsvQueryResponse.builder().vulns(List.of(vuln)).build());

    when(osvAdvisoryRepository.findByOsvId("GHSA-35jh-r3h4-6jhm"))
        .thenReturn(java.util.Optional.of(OsvAdvisoryEntity.builder().build()));

    service.syncOsvAdvisories();

    verify(osvAdvisoryRepository, never()).save(any(OsvAdvisoryEntity.class));
  }
}
