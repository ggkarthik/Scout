package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@PostgresIntegrationTest
class AiGridFindingsRepairPostgresIntegrationTest {
    static final LocalPostgresTestDatabase.DatabaseConfig DATABASE=LocalPostgresTestDatabase.provision("ai_findings_repair");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry,DATABASE); registry.add("app.ai-grid.assessment.lease-seconds",() -> "2"); registry.add("app.ai-grid.assessment.heartbeat-seconds",() -> "1"); }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService execution;
    @Autowired NamedParameterJdbcTemplate jdbc;
    @Autowired TransactionTemplate transactions;
    @Autowired AiGridAssessmentService assessments;
    @Autowired AiGridAssessmentWorker worker;
    @Autowired AiGridApiService api;
    @Autowired AiSecurityApiService compatibility;
    @Autowired AiGridCoverageService coverage;
    @Autowired AiSecurityDigestBaselineService baselines;

    @Test void allSeededVersionMismatchesResolveToTheDistributedVersion() {
        Tenant tenant=tenant();
        execution.run(tenant,() -> {
            List<String> mismatches=jdbc.query("""
                    select d.policy_id from platform.ai_grid_policy_distribution d
                      join lateral (select version from platform.ai_grid_policy_versions v where v.policy_id=d.policy_id
                          order by published_at desc,version desc limit 1) old on true
                     where d.available and d.rollout_stage='GENERAL_AVAILABILITY' and old.version<>d.pinned_version
                       and d.policy_id not like 'RESOLUTION_%'
                    """,(rs,row) -> rs.getString(1));
            assertEquals(16,mismatches.size(),"Seeded unpublished replacements previously displaced sixteen pins");
            Map<String,String> resolved=new java.util.HashMap<>();
            jdbc.query("select policy_id,version from "+AiGridPolicyResolution.versions(":tenantId")+" p",
                    Map.of("tenantId",tenant.getId()),rs -> { resolved.put(rs.getString(1),rs.getString(2)); });
            for (String id:mismatches) {
                String pin=jdbc.queryForObject("select pinned_version from platform.ai_grid_policy_distribution where policy_id=:id",Map.of("id",id),String.class);
                assertEquals(pin,resolved.get(id),id);
                assertEquals(pin,api.policies(tenant).stream().filter(policy -> policy.policyId().equals(id)).findFirst().orElseThrow().version());
            }
        });
    }

    @Test void malformedAndSqlFailingPoliciesRollbackIndependentlyAndLeavePriorFindingsUnchanged() {
        Tenant tenant=tenant(); String suffix=UUID.randomUUID().toString();
        String healthy="HEALTHY_"+suffix, malformed="BAD_RULE_"+suffix, sqlFailure="SQL_FAILURE_"+suffix;
        policy(healthy,"{\"fact\":\"test.failure\",\"eq\":true}");
        policy(sqlFailure,"{\"fact\":\"test.failure\",\"eq\":true}");
        policy(malformed,"{\"notAnOperator\":true}");
        execution.run(tenant,() -> {
            Snapshot first=snapshot(tenant,"AWS:one",Instant.now(),true);
            var initial=assessments.evaluateCurrent(tenant,first.runId(),Set.of(sqlFailure),() -> {});
            assertEquals(1,initial.assessedSubjects());
            UUID priorAssessment=jdbc.queryForObject("select assessment_id from findings where policy_id=:id",Map.of("id",sqlFailure),UUID.class);
            String priorEvidence=jdbc.queryForObject("select evidence::text from findings where policy_id=:id",Map.of("id",sqlFailure),String.class);
            String schema=TenantContext.getCurrentSchemaName();
            jdbc.getJdbcTemplate().execute("create function "+schema+".fail_repair_assessment() returns trigger language plpgsql as $$ begin if NEW.policy_id='"+sqlFailure+"' and NEW.subject_type='ARTIFACT' then raise exception 'private SQL detail' using errcode='23514'; end if; return NEW; end $$");
            jdbc.getJdbcTemplate().execute("create trigger reject_repair_policy before insert on "+schema+".ai_grid_assessments for each row execute function "+schema+".fail_repair_assessment()");
            Snapshot next=snapshot(tenant,"AWS:one",Instant.now(),true);
            var result=assessments.evaluateCurrent(tenant,next.runId(),Set.of(healthy,malformed,sqlFailure),() -> {});
            assertEquals("PARTIAL",result.assessmentStatus()); assertEquals(2,result.failedPolicies()); assertEquals(1,result.assessedSubjects());
            assertEquals(1,count("select count(*) from ai_grid_snapshot_manifests where run_id='"+next.runId()+"'"));
            assertEquals(0,count("select count(*) from ai_grid_assessments where run_id='"+next.runId()+"' and policy_id='"+sqlFailure+"' and subject_type='ARTIFACT'"));
            assertEquals(priorAssessment,jdbc.queryForObject("select assessment_id from findings where policy_id=:id",Map.of("id",sqlFailure),UUID.class));
            assertEquals(priorEvidence,jdbc.queryForObject("select evidence::text from findings where policy_id=:id",Map.of("id",sqlFailure),String.class));
            assertEquals(2,count("select count(*) from ai_grid_coverage_gaps where state='POLICY_EVALUATION_ERROR' and artifact_id is null and status='OPEN'"));
            assertEquals(2,count("select count(*) from ai_grid_assessments where reason_code='POLICY_EVALUATION_ERROR' and decision='ERROR'"));
            var bad=assertThrows(ResponseStatusException.class,() -> api.updateSelection(tenant,malformed,"ENABLED","owner","invalid edit"));
            assertEquals(400,bad.getStatusCode().value());
            assertDoesNotThrow(() -> api.updateSelection(tenant,healthy,"ENABLED","owner","healthy edit"));
            assertEquals("COMPLETE",worker.policyStatus(tenant,healthy).assessmentStatus());
            assertTrue(compatibility.findings(tenant,healthy,"OPEN",0,10).total()>0);
        });
    }

    @Test void currentReassessmentUsesMultipleScopeHeadsAndExpiredEvidenceCannotOpenFindings() {
        Tenant tenant=tenant(); String id="FRESHNESS_"+UUID.randomUUID();
        policy(id,"{\"fact\":\"test.failure\",\"eq\":true}");
        execution.run(tenant,() -> {
            Snapshot stale=snapshot(tenant,"AWS:stale",Instant.now().minusSeconds(7200),true);
            Snapshot fresh=snapshot(tenant,"AWS:fresh",Instant.now(),true);
            var result=assessments.evaluateCurrent(tenant,fresh.runId(),Set.of(id),() -> {});
            assertEquals(2,result.assessedSubjects());
            assertEquals(1,count("select count(*) from findings where policy_id='"+id+"' and status='OPEN'"));
            assertEquals("STALE",jdbc.queryForObject("select evidence_readiness from ai_grid_assessments where policy_id=:id and subject_id=:artifact",Map.of("id",id,"artifact",stale.artifactId()),String.class));
            assertEquals(1,count("select count(*) from ai_grid_assessments where policy_id='"+id+"' and subject_id='"+fresh.artifactId()+"' and decision='FAIL'"));
            assessments.evaluateHistorical(tenant,stale.runId());
            assertEquals(1,count("select count(*) from findings where policy_id='"+id+"' and status='OPEN'"),"historical replay cannot open a newer current finding");
            api.updateSelection(tenant,id,"PREVIEW","owner","withdraw");
            assertEquals(0,count("select count(*) from findings where policy_id='"+id+"' and status='OPEN'"));
        });
    }

    @Test void savedPlatformDefaultsAreIgnoredWhileExplicitTenantOverridesWin() {
        Tenant tenant=tenant(); String id="SELECTION_"+UUID.randomUUID(); policy(id,"{\"fact\":\"test.failure\",\"eq\":true}");
        TenantContext.runAsPlatform(() -> jdbc.update("update platform.ai_grid_policy_distribution set default_selection='PREVIEW' where policy_id=:id",Map.of("id",id)));
        execution.run(tenant,() -> {
            jdbc.update("insert into ai_grid_policy_selections(policy_id,tenant_id,selection,configuration_source,updated_by) values (:id,:tenant,'ENABLED','PLATFORM_DEFAULT','test')",Map.of("id",id,"tenant",tenant.getId()));
            Snapshot snapshot=snapshot(tenant,"AWS:selection",Instant.now(),true);
            assessments.evaluateCurrent(tenant,snapshot.runId(),Set.of(id),() -> {});
            assertEquals(0,count("select count(*) from findings where policy_id='"+id+"'"));
            assertEquals("PREVIEW",api.policies(tenant).stream().filter(policy -> policy.policyId().equals(id)).findFirst().orElseThrow().selection());
            api.updateSelection(tenant,id,"ENABLED","owner","override");
            assertEquals(1,count("select count(*) from findings where policy_id='"+id+"' and status='OPEN'"));
        });
    }

    @Test void claimsFilterEventTypesRecoverExpiredLeasesAndFenceTheOldWorker() {
        Tenant tenant=tenant();
        execution.run(tenant,() -> {
            UUID run=UUID.randomUUID(); UUID request=request(tenant,run,AiGridAssessmentWorker.EVENT_TYPE);
            UUID unrelated=request(tenant,run,"SNAPSHOT_COMMITTED");
            var first=transactions.execute(status -> worker.claim(request)); assertNotNull(first);
            assertNull(transactions.execute(status -> worker.claim(request)),"duplicate delivery cannot steal a live lease");
            assertNull(transactions.execute(status -> worker.claim(unrelated)),"worker must leave other outbox families untouched");
            jdbc.update("update ai_grid_outbox set available_at=now()-interval '1 second' where id=:id",Map.of("id",request));
            var reclaimed=transactions.execute(status -> worker.claim(request)); assertNotNull(reclaimed);
            assertNotEquals(first.token(),reclaimed.token()); assertEquals(2,reclaimed.attempt());
            assertThrows(AiGridAssessmentWorker.LeaseLostException.class,() -> transactions.executeWithoutResult(status -> worker.assertLease(first)));
            worker.process(tenant,first);
            assertDoesNotThrow(() -> transactions.executeWithoutResult(status -> worker.assertLease(reclaimed)));
            assertEquals("PENDING",jdbc.queryForObject("select status from ai_grid_outbox where id=:id",Map.of("id",unrelated),String.class));
        });
    }

    @Test void concurrentInstancesClaimDistinctRequestsAndDoNotCrossTenantSchemas() throws Exception {
        Tenant one=tenant(), two=tenant(); UUID requestOne=execution.run(one,() -> request(one,UUID.randomUUID(),AiGridAssessmentWorker.EVENT_TYPE));
        UUID requestTwo=execution.run(one,() -> request(one,UUID.randomUUID(),AiGridAssessmentWorker.EVENT_TYPE));
        UUID isolated=execution.run(two,() -> request(two,UUID.randomUUID(),AiGridAssessmentWorker.EVENT_TYPE));
        var pool=Executors.newFixedThreadPool(2);
        try {
            var a=pool.submit(() -> execution.run(one,() -> transactions.execute(status -> worker.claim(null))));
            var b=pool.submit(() -> execution.run(one,() -> transactions.execute(status -> worker.claim(null))));
            Set<UUID> claimed=Set.of(a.get(10,TimeUnit.SECONDS).id(),b.get(10,TimeUnit.SECONDS).id());
            assertEquals(Set.of(requestOne,requestTwo),claimed);
            assertEquals("PENDING",execution.run(two,() -> jdbc.queryForObject("select status from ai_grid_outbox where id=:id",Map.of("id",isolated),String.class)));
        } finally { pool.shutdownNow(); }
    }

    @Test void heartbeatKeepsLongPolicyTransactionsAliveAndCompletedDeliveryIsIdempotent() {
        Tenant tenant=tenant(); String id="SLOW_"+UUID.randomUUID(); policy(id,"{\"fact\":\"test.failure\",\"eq\":true}");
        execution.run(tenant,() -> {
            Snapshot source=snapshot(tenant,"AWS:slow",Instant.now(),true);
            String schema=TenantContext.getCurrentSchemaName();
            jdbc.getJdbcTemplate().execute("create function "+schema+".slow_policy() returns trigger language plpgsql as $$ begin if NEW.policy_id='"+id+"' and NEW.subject_type='ARTIFACT' then perform pg_sleep(3); end if; return NEW; end $$");
            jdbc.getJdbcTemplate().execute("create trigger slow_policy before insert on "+schema+".ai_grid_assessments for each row execute function "+schema+".slow_policy()");
            UUID request=request(tenant,source.runId(),AiGridAssessmentWorker.EVENT_TYPE);
            jdbc.update("update ai_grid_outbox set payload_json=jsonb_set(payload_json,'{policyIds}',cast(:policies as jsonb)) where id=:id",Map.of("id",request,"policies","[\""+id+"\"]"));
            var claim=transactions.execute(status -> worker.claim(request)); assertNotNull(claim);
            worker.process(tenant,claim);
            assertEquals("COMPLETE",worker.status(tenant,source.runId()).assessmentStatus());
            assertEquals(1,worker.status(tenant,source.runId()).assessedSubjects());
            assertEquals("PROCESSED",jdbc.queryForObject("select status from ai_grid_outbox where id=:id",Map.of("id",request),String.class));
            UUID assessment=jdbc.queryForObject("select assessment_id from findings where policy_id=:id",Map.of("id",id),UUID.class);
            worker.dispatch(tenant,request);
            assertEquals(assessment,jdbc.queryForObject("select assessment_id from findings where policy_id=:id",Map.of("id",id),UUID.class));
            assertEquals(1,count("select count(*) from findings where policy_id='"+id+"'"));
        });
    }

    @Test void exhaustedInterruptedRequestsRemainInspectableUntilExplicitReplay() {
        Tenant tenant=tenant();
        execution.run(tenant,() -> {
            UUID request=request(tenant,UUID.randomUUID(),AiGridAssessmentWorker.EVENT_TYPE);
            jdbc.update("update ai_grid_outbox set attempts=5,status='PROCESSING',available_at=now()-interval '1 second' where id=:id",Map.of("id",request));
            assertNull(transactions.execute(status -> worker.claim(request)));
            assertEquals("FAILED",jdbc.queryForObject("select status from ai_grid_outbox where id=:id",Map.of("id",request),String.class));
            worker.replayFailure(tenant,request);
            var replay=transactions.execute(status -> worker.claim(request)); assertNotNull(replay); assertEquals(1,replay.attempt());
        });
    }

    @Test void unpinnedVersionsCanaryVisibilityAndRevokedApprovalRemainConsistent() {
        Tenant one=tenant(),two=tenant(); String id="RESOLUTION_"+UUID.randomUUID();
        policy(id,"{\"fact\":\"test.failure\",\"eq\":true}");
        TenantContext.runAsPlatform(() -> {
            jdbc.update("""
                    insert into platform.ai_grid_policy_versions(policy_id,version,name,description,severity,lifecycle,workflow_class,
                        default_selection,artifact_types_json,required_resource_families_json,required_facts_json,predicate_json,reason_code,remediation)
                    select policy_id,'2.0.0',name,description,severity,'VALIDATED',workflow_class,default_selection,
                        artifact_types_json,required_resource_families_json,required_facts_json,predicate_json,reason_code,remediation
                      from platform.ai_grid_policy_versions where policy_id=:id and version='1.0.0'
                    """,Map.of("id",id));
            jdbc.getJdbcTemplate().execute("alter table platform.ai_grid_policy_distribution disable trigger trg_ai_grid_distribution_approval");
            try { jdbc.update("update platform.ai_grid_policy_distribution set pinned_version=null where policy_id=:id",Map.of("id",id)); }
            finally { jdbc.getJdbcTemplate().execute("alter table platform.ai_grid_policy_distribution enable trigger trg_ai_grid_distribution_approval"); }
        });
        assertEquals("1.0.0",api.policies(one).stream().filter(policy -> policy.policyId().equals(id)).findFirst().orElseThrow().version());
        TenantContext.runAsPlatform(() -> jdbc.update("update platform.ai_grid_policy_distribution set pinned_version='1.0.0',rollout_stage='CANARY',canary_tenant_ids_json=cast(:cohort as jsonb) where policy_id=:id",Map.of("id",id,"cohort","[\""+one.getId()+"\"]")));
        assertTrue(api.policies(one).stream().anyMatch(policy -> policy.policyId().equals(id)));
        assertFalse(api.policies(two).stream().anyMatch(policy -> policy.policyId().equals(id)));
        UUID decision=UUID.randomUUID(),binding=UUID.randomUUID(); String digest="a".repeat(64);
        TenantContext.runAsPlatform(() -> {
            jdbc.update("insert into platform.ai_grid_policy_release_decisions(id,policy_id,policy_version,decision,reason,decided_by,package_digest,approved_package_digest) values (:decision,:id,'1.0.0','APPROVED','test','owner',:digest,:digest)",Map.of("id",id,"decision",decision,"digest",digest));
            jdbc.update("update platform.ai_grid_policy_versions set package_digest=:digest where policy_id=:id and version='1.0.0'",Map.of("id",id,"digest",digest));
            jdbc.update("update platform.ai_grid_policy_distribution set release_decision_id=:decision,approved_package_digest=:digest where policy_id=:id",Map.of("id",id,"decision",decision,"digest",digest));
            jdbc.update("""
                    insert into platform.ai_grid_policy_release_bindings(id,approval_decision_id,policy_id,policy_version,
                        approved_package_digest,distribution_snapshot_json,target_tenant_ids_json,bound_by)
                    values (:binding,:decision,:id,'1.0.0',:digest,'{}'::jsonb,cast(:targets as jsonb),'owner')
                    """,Map.of("binding",binding,"decision",decision,"id",id,"digest",digest,"targets","[\""+one.getId()+"\"]"));
        });
        assertTrue(api.policies(one).stream().anyMatch(policy -> policy.policyId().equals(id)));
        TenantContext.runAsPlatform(() -> jdbc.update("update platform.ai_grid_policy_release_bindings set state='REVOKED',revoked_at=now(),revoked_by='owner',revocation_reason='test' where id=:id",Map.of("id",binding)));
        assertFalse(api.policies(one).stream().anyMatch(policy -> policy.policyId().equals(id)));
    }

    @Test void baselineObservationSurvivesFindingFailureAndApprovalRevocationIsReconciledAfterCommit() {
        Tenant tenant=tenant();
        execution.run(tenant,() -> {
            Snapshot source=snapshot(tenant,"AWS:baseline",Instant.now(),true);
            jdbc.update("insert into ai_security_observation_receipts(id,tenant_id,run_id,scope_key,chunk_sequence,idempotency_key,content_hash) values (gen_random_uuid(),:tenant,:run,'AWS:baseline',0,cast(:run as text),'baseline-receipt')",Map.of("tenant",tenant.getId(),"run",source.runId()));
            transactions.executeWithoutResult(status -> baselines.observeCurrentTenant(tenant,source.artifactId(),"PROMPT","HMAC-SHA256","key1","digest-a",source.runId(),Instant.now()));
            baselines.approve(tenant,source.artifactId(),new AiSecurityDigestBaselineService.Request("PROMPT","HMAC-SHA256","key1","digest-a",source.runId()),"owner",false);
            String schema=TenantContext.getCurrentSchemaName();
            jdbc.getJdbcTemplate().execute("create function "+schema+".reject_baseline() returns trigger language plpgsql as $$ begin if NEW.policy_id='AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL' then raise exception 'baseline constraint' using errcode='23514'; end if; return NEW; end $$");
            jdbc.getJdbcTemplate().execute("create trigger reject_baseline before insert on "+schema+".ai_grid_assessments for each row execute function "+schema+".reject_baseline()");
            transactions.executeWithoutResult(status -> baselines.observeCurrentTenant(tenant,source.artifactId(),"PROMPT","HMAC-SHA256","key1","digest-b",source.runId(),Instant.now()));
            assertEquals("digest-b",jdbc.queryForObject("select observed_digest from ai_security_artifact_digest_observations where artifact_id=:id",Map.of("id",source.artifactId()),String.class));
            assertEquals("FAILED",worker.policyStatus(tenant,"AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL").assessmentStatus());
            assertEquals(0,count("select count(*) from findings where policy_id='AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL'"));
            jdbc.getJdbcTemplate().execute("drop trigger reject_baseline on "+schema+".ai_grid_assessments");
            UUID failed=jdbc.queryForObject("select id from ai_grid_outbox where event_type='STATIC_ASSESSMENT_REQUESTED' and status='FAILED' order by created_at desc,id desc limit 1",Map.of(),UUID.class);
            worker.replayFailure(tenant,failed); worker.dispatch(tenant,failed);
            assertEquals(1,count("select count(*) from findings where policy_id='AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL' and status='OPEN'"));
            baselines.revoke(tenant,source.artifactId(),"PROMPT","owner");
            assertEquals(0,count("select count(*) from findings where policy_id='AI_ARTIFACT_DIGEST_CHANGED_AFTER_APPROVAL' and status='OPEN'"));
            assertEquals("REVOKED",baselines.list(tenant,source.artifactId()).get(0).approvalStatus());
        });
    }

    private Tenant tenant() {
        Tenant tenant=tenants.createTenant("Repair "+UUID.randomUUID(),"repair-"+UUID.randomUUID(),"pilot",null);
        migrations.provisionNewTenant(tenant); return tenant;
    }
    private void policy(String id,String predicate) {
        TenantContext.runAsPlatform(() -> {
            jdbc.update("""
                    insert into platform.ai_grid_policy_versions(policy_id,version,name,description,severity,lifecycle,workflow_class,
                      default_selection,artifact_types_json,native_kinds_json,required_resource_families_json,required_facts_json,
                      predicate_json,reason_code,remediation,published_at)
                    values (:id,'1.0.0','Repair policy','Test','HIGH','PUBLISHED','POSTURE_FINDING','ENABLED',
                      '["AI_AGENT"]'::jsonb,'[]'::jsonb,'[]'::jsonb,
                      '[{"factKey":"test.failure","valueType":"BOOLEAN","evidenceClasses":["CONFIGURATION"],"maxAgeSeconds":3600}]'::jsonb,
                      cast(:predicate as jsonb),'TEST_FAILURE','Fix',now())
                    """,Map.of("id",id,"predicate",predicate));
            jdbc.update("insert into platform.ai_grid_policy_distribution(policy_id,available,default_selection,pinned_version) values (:id,true,'ENABLED','1.0.0')",Map.of("id",id));
        });
    }
    private Snapshot snapshot(Tenant tenant,String scope,Instant observed,boolean fails) {
        return transactions.execute(status -> {
            UUID run=UUID.randomUUID(), artifact=UUID.randomUUID(), body=UUID.randomUUID(),manifest=UUID.randomUUID();
            var params=new MapSqlParameterSource().addValue("tenant",tenant.getId()).addValue("run",run).addValue("artifact",artifact)
                    .addValue("body",body).addValue("manifest",manifest).addValue("scope",scope).addValue("observed",Timestamp.from(observed));
            jdbc.update("""
                    insert into ai_security_artifacts(id,tenant_id,provider,provider_resource_id,artifact_type,native_kind,name,account_id,region,first_observed_at,last_observed_at)
                    values (:artifact,:tenant,'AWS',cast(:artifact as text),'AI_AGENT','AWS_BEDROCK_AGENT','Repair agent','123456789012','us-east-1',:observed,:observed)
                    """,params);
            jdbc.update("""
                    insert into ai_grid_snapshot_bodies(id,tenant_id,content_hash,byte_size,redaction_profile,content_json)
                    values (:body,:tenant,cast(:body as text),128,'STATIC_METADATA_V1','{"artifactType":"AI_AGENT","nativeKind":"AWS_BEDROCK_AGENT","accountId":"123456789012","region":"us-east-1"}'::jsonb)
                    """,params);
            jdbc.update("insert into ai_grid_snapshot_manifests(id,tenant_id,run_id,artifact_id,scope_key,body_id,schema_version,observed_at) values (:manifest,:tenant,:run,:artifact,:scope,:body,'1.0.0',:observed)",params);
            jdbc.update("""
                    insert into ai_security_snapshot_scopes(id,tenant_id,run_id,provider,account_id,region,resource_family,scope_key,status,started_at,completed_at)
                    values (gen_random_uuid(),:tenant,:run,'AWS','123456789012','us-east-1','AWS_BEDROCK_AGENT',:scope,'COMPLETE',:observed,:observed)
                    """,params);
            jdbc.update("""
                    insert into ai_grid_facts(id,tenant_id,run_id,artifact_id,snapshot_manifest_id,fact_key,value_type,value_json,state,provenance,evidence_class,source,observed_at,fact_schema_version)
                    values (gen_random_uuid(),:tenant,:run,:artifact,:manifest,'test.failure','BOOLEAN',cast(:value as jsonb),'KNOWN','PROVIDER_API','CONFIGURATION','test',:observed,'1.0.0')
                    """,params.addValue("value",Boolean.toString(fails)));
            return new Snapshot(run,artifact,manifest);
        });
    }
    private UUID request(Tenant tenant,UUID run,String type) {
        UUID id=UUID.randomUUID();
        jdbc.update("insert into ai_grid_outbox(id,tenant_id,event_type,aggregate_type,aggregate_id,aggregate_version,payload_json) values (:id,:tenant,:type,'ASSESSMENT_RUN',:run,cast(:id as text),'{\"policyIds\":[],\"assessmentStatus\":\"PENDING\"}'::jsonb)",Map.of("id",id,"tenant",tenant.getId(),"type",type,"run",run)); return id;
    }
    private long count(String sql) { return jdbc.queryForObject(sql,Map.of(),Long.class); }
    private record Snapshot(UUID runId,UUID artifactId,UUID manifestId) {}
}
