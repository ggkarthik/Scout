package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiAgentDeploymentService.*;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

class AiAgentDeploymentBatchTest {
    @Test void lookupQueryCountIsConstantForOneAndOneHundredAgents() throws Exception {
        UUID root = UUID.randomUUID(), run = UUID.randomUUID(), version = UUID.randomUUID(), route = UUID.randomUUID();
        Instant now = Instant.parse("2026-10-05T12:00:00Z");
        ObjectMapper mapper = new ObjectMapper();
        for (int size : List.of(1, 100)) {
            NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
            when(jdbc.queryForObject(anyString(), anyMap(), eq(Integer.class))).thenReturn(24);
            when(jdbc.query(anyString(), anyMap(), org.mockito.ArgumentMatchers.<RowMapper<Object>>any())).thenAnswer(call -> {
                String sql = call.getArgument(0);
                if (sql.contains("with applicable")) return List.of(new Scope(root,UUID.randomUUID(),run,"BEDROCK_AGENT_ROUTES","COMPLETE",null,now,true));
                if (sql.contains("select r.run_id")) return List.of(new Edge(run,root,route,"HAS_COMPONENT"),new Edge(run,route,version,"SERVES_VERSION"),new Edge(run,version,root,"VERSION_OF"));
                return List.of(new Resource(run,root,"AWS_BEDROCK_AGENT",mapper.readTree("{}")),
                        new Resource(run,version,"AWS_BEDROCK_AGENT_VERSION",mapper.readTree("{}")),
                        new Resource(run,route,"AWS_BEDROCK_AGENT_ALIAS",mapper.readTree("{\"status\":\"PREPARED\",\"invocationState\":\"ACCEPT_INVOCATIONS\"}")));
            });
            List<Agent> agents = IntStream.range(0,size).mapToObj(index -> new Agent(index == 0 ? root : UUID.randomUUID(),"AWS_BEDROCK_AGENT")).toList();
            Map<UUID, Metadata> metadata = new AiAgentDeploymentService(jdbc,mapper).resolve(agents,now);
            assertEquals(size,metadata.size());
            assertEquals(Status.SERVED,metadata.get(root).status());
            assertEquals(5,mockingDetails(jdbc).getInvocations().stream().filter(i -> i.getMethod().getName().startsWith("query")).count());
        }
    }
    @Test void ambiguousCompleteAttemptPreservesEarlierVerifiedHistory() throws Exception {
        UUID root = UUID.randomUUID(), oldRun = UUID.randomUUID(), latestRun = UUID.randomUUID();
        Instant now = Instant.parse("2026-10-05T12:00:00Z");
        NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
        ObjectMapper mapper = new ObjectMapper();
        when(jdbc.queryForObject(anyString(),anyMap(),eq(Integer.class))).thenReturn(24);
        when(jdbc.query(anyString(),anyMap(),org.mockito.ArgumentMatchers.<RowMapper<Object>>any())).thenAnswer(call -> {
            String sql = call.getArgument(0);
            if (sql.contains("with applicable")) return List.of(
                    new Scope(root,UUID.randomUUID(),latestRun,"BEDROCK_AGENT_ROUTES","COMPLETE",null,now,true),
                    new Scope(root,UUID.randomUUID(),oldRun,"BEDROCK_AGENT_ROUTES","COMPLETE",null,now.minusSeconds(60),true));
            if (sql.contains("select r.run_id")) return List.of();
            return List.of(new Resource(oldRun,root,"AWS_BEDROCK_AGENT",mapper.readTree("{}")));
        });
        Metadata metadata = new AiAgentDeploymentService(jdbc,mapper).resolve(List.of(new Agent(root,"AWS_BEDROCK_AGENT")),now).get(root);
        assertEquals(Status.UNVERIFIED,metadata.status());
        assertEquals(Status.NOT_CURRENTLY_SERVED,metadata.lastVerifiedObservation().status());
        assertEquals(now.minusSeconds(60),metadata.lastVerifiedObservation().observedAt());
    }
    @Test void supportingResourcesNeverTriggerDeploymentLookups() {
        NamedParameterJdbcTemplate jdbc = mock(NamedParameterJdbcTemplate.class);
        assertTrue(new AiAgentDeploymentService(jdbc,new ObjectMapper()).resolve(
                List.of(new Agent(UUID.randomUUID(),"AZURE_BOT_SERVICES")),Instant.now()).isEmpty());
        verifyNoInteractions(jdbc);
    }
}
