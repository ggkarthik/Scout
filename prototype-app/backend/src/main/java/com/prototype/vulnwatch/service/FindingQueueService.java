package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingQueueDefinitionResponse;
import com.prototype.vulnwatch.dto.FindingQueueUpsertRequest;
import com.prototype.vulnwatch.dto.FindingsFilter;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingQueueService {

    private final FindingQueueDefinitionService findingQueueDefinitionService;
    private final PersonalFindingQueueService personalFindingQueueService;
    private final FindingQueueResolutionService findingQueueResolutionService;

    public FindingQueueService(
            FindingQueueDefinitionService findingQueueDefinitionService,
            PersonalFindingQueueService personalFindingQueueService,
            FindingQueueResolutionService findingQueueResolutionService
    ) {
        this.findingQueueDefinitionService = findingQueueDefinitionService;
        this.personalFindingQueueService = personalFindingQueueService;
        this.findingQueueResolutionService = findingQueueResolutionService;
    }

    @Transactional(readOnly = true)
    public List<FindingQueueDefinitionResponse> listQueues(Tenant tenant) {
        String defaultQueueRef = personalFindingQueueService.currentDefaultQueueRef(tenant).orElse(null);
        List<FindingQueueDefinitionResponse> builtIns = findingQueueDefinitionService.listBuiltInQueues(tenant, defaultQueueRef);
        List<FindingQueueDefinitionResponse> personal = personalFindingQueueService.listQueues(tenant, defaultQueueRef);
        return java.util.stream.Stream.concat(builtIns.stream(), personal.stream()).toList();
    }

    @Transactional(readOnly = true)
    public FindingQueueDefinitionResponse getQueue(Tenant tenant, String queueRef) {
        String defaultQueueRef = personalFindingQueueService.currentDefaultQueueRef(tenant).orElse(null);
        return findingQueueDefinitionService.getBuiltInQueue(tenant, queueRef, defaultQueueRef)
                .orElseGet(() -> personalFindingQueueService.getQueue(tenant, queueRef, defaultQueueRef));
    }

    @Transactional
    public FindingQueueDefinitionResponse createQueue(Tenant tenant, FindingQueueUpsertRequest request) {
        return personalFindingQueueService.createQueue(tenant, request);
    }

    @Transactional
    public FindingQueueDefinitionResponse updateQueue(Tenant tenant, String queueRef, FindingQueueUpsertRequest request) {
        if (findingQueueDefinitionService.isBuiltIn(queueRef)) {
            throw new IllegalArgumentException("Built-in queues cannot be modified");
        }
        return personalFindingQueueService.updateQueue(tenant, queueRef, request);
    }

    @Transactional
    public FindingQueueDefinitionResponse duplicateQueue(Tenant tenant, String queueRef) {
        if (findingQueueDefinitionService.isBuiltIn(queueRef)) {
            throw new IllegalArgumentException("Built-in queues cannot be modified");
        }
        return personalFindingQueueService.duplicateQueue(tenant, queueRef);
    }

    @Transactional
    public void deleteQueue(Tenant tenant, String queueRef) {
        if (findingQueueDefinitionService.isBuiltIn(queueRef)) {
            throw new IllegalArgumentException("Built-in queues cannot be modified");
        }
        personalFindingQueueService.deleteQueue(tenant, queueRef);
    }

    @Transactional
    public void setDefaultQueue(Tenant tenant, String queueRef) {
        personalFindingQueueService.setDefaultQueue(tenant, queueRef);
    }

    @Transactional(readOnly = true)
    public FindingsFilter resolveEffectiveFilter(String queueRef, FindingsFilter adHocFilter) {
        return findingQueueResolutionService.resolveEffectiveFilter(queueRef, adHocFilter);
    }
}
