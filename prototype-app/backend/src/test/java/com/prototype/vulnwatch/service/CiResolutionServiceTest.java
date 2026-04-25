package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

class CiResolutionServiceTest {

    @Test
    void batchResolvePreservesCachedOwnershipWithoutServiceNowSysIdLookup() {
        String sysId = "b4fd7c8437201000deeabfc8bcbe5dc1";
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");

        Asset cachedAsset = new Asset();
        cachedAsset.setTenant(tenant);
        cachedAsset.setIdentifier("ci:" + sysId);
        cachedAsset.setName("*ANNIE-IBM");
        cachedAsset.setOwnerEmail("Alene Rabeck");
        cachedAsset.setSupportGroup("App Engine Admins");

        Ci cachedCi = new Ci();
        cachedCi.setTenant(tenant);
        cachedCi.setAsset(cachedAsset);
        cachedCi.setSysId(sysId);
        cachedCi.setDisplayName("*ANNIE-IBM");
        cachedCi.setOwnerEmail("Alene Rabeck");
        cachedCi.setSupportGroup("App Engine Admins");

        Map<String, Ci> ciBySysId = new LinkedHashMap<>();
        ciBySysId.put(sysId, cachedCi);

        AssetRepository assetRepository = mock(AssetRepository.class);
        CiRepository ciRepository = mock(CiRepository.class);
        CiAliasRepository ciAliasRepository = mock(CiAliasRepository.class);
        ServiceNowCmdbConfigService configService = mock(ServiceNowCmdbConfigService.class);
        when(assetRepository.save(any(Asset.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciRepository.save(any(Ci.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(ciAliasRepository.save(any(CiAlias.class))).thenAnswer(invocation -> invocation.getArgument(0));

        RestTemplate restTemplate = new RestTemplate();
        CiResolutionService service = new CiResolutionService(
                ciRepository,
                ciAliasRepository,
                assetRepository,
                new OutboundHttpClient(restTemplate),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0L, 1, 1L, 60_000L, true, true)),
                new ObjectMapper(),
                configService
        );
        CiResolutionService.BatchResolutionContext context = new CiResolutionService.BatchResolutionContext(
                tenant,
                "servicenow",
                ciBySysId,
                new LinkedHashMap<>(),
                new LinkedHashMap<>(),
                new LinkedHashMap<>()
        );

        CiResolutionService.Resolution firstResolution = service.resolve(
                context,
                tenant,
                sysId,
                "*ANNIE-IBM",
                null,
                CiResolutionService.OwnershipDetails.empty(),
                BusinessCriticality.MEDIUM,
                "servicenow"
        );
        CiResolutionService.Resolution secondResolution = service.resolve(
                context,
                tenant,
                sysId,
                "*ANNIE-IBM",
                null,
                CiResolutionService.OwnershipDetails.empty(),
                BusinessCriticality.MEDIUM,
                "servicenow"
        );

        assertEquals("Alene Rabeck", firstResolution.ci().getOwnerEmail());
        assertEquals("App Engine Admins", firstResolution.ci().getSupportGroup());
        assertEquals("Alene Rabeck", firstResolution.ci().getAsset().getOwnerEmail());
        assertEquals("App Engine Admins", firstResolution.ci().getAsset().getSupportGroup());
        assertEquals("Alene Rabeck", secondResolution.ci().getOwnerEmail());
        assertEquals("App Engine Admins", secondResolution.ci().getSupportGroup());
        verifyNoInteractions(configService);
    }
}
