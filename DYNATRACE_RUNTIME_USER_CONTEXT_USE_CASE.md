# Dynatrace Runtime and User-Behavior Context for Open-Source Vulnerability Risk

## Objective

Identify open-source libraries running in an application and use runtime, transaction, and user-behavior context to assess their actual vulnerability risk. Log4j and Log4Shell (`CVE-2021-44228`) are the primary examples.

This is a future integration design only. It does not implement or enable the Dynatrace integration.

## Context Model

The use case requires correlating three Dynatrace datasets:

1. **Runtime Vulnerability Analytics** identifies whether Log4j is loaded, vulnerable, exposed, and whether a vulnerable function is in use.
2. **Distributed traces** identify the services, endpoints, and transactions that pass through the affected runtime.
3. **Real User Monitoring (RUM)** identifies the user actions and sessions that initiated those transactions.

An important distinction must be preserved:

- **Observed path:** A user transaction reached a service running a vulnerable Log4j component.
- **Confirmed invocation:** The transaction invoked the vulnerable function, produced a correlated security finding, or emitted trace-linked instrumentation evidence.

A transaction reaching an affected service does not, by itself, prove that the transaction invoked a vulnerable Log4j function. Dynatrace generally reports vulnerable-function usage at the process-group level rather than for each individual trace.

## Prerequisites

The Dynatrace environment should have:

- OneAgent full-stack monitoring on the Java processes.
- Runtime Vulnerability Analytics enabled.
- Java vulnerable-function monitoring enabled.
- Deep monitoring and distributed tracing enabled.
- RUM JavaScript deployed in the frontend.
- RUM-to-backend trace correlation enabled through W3C Trace Context or Dynatrace `server-timing` headers.
- An Environment API token with the `securityProblems.read` scope.
- OAuth access to the Grail Query API.
- Permission to read the Grail `spans` and `user.events` tables.

Dynatrace documentation:

- [Runtime Vulnerability Analytics](https://docs.dynatrace.com/docs/secure/application-security/vulnerability-analytics)
- [Vulnerability evaluation](https://docs.dynatrace.com/docs/secure/application-security/vulnerability-analytics/vulnerability-evaluation)

## 1. Find the Log4j Vulnerability

Use the Environment API to find an open Log4Shell vulnerability:

```bash
curl --get \
  "https://${DT_ENVIRONMENT_ID}.live.dynatrace.com/api/v2/securityProblems" \
  -H "Authorization: Api-Token ${DT_API_TOKEN}" \
  --data-urlencode 'securityProblemSelector=status("OPEN"),cveId("CVE-2021-44228")'
```

To retrieve all open Java third-party vulnerabilities:

```bash
curl --get \
  "https://${DT_ENVIRONMENT_ID}.live.dynatrace.com/api/v2/securityProblems" \
  -H "Authorization: Api-Token ${DT_API_TOKEN}" \
  --data-urlencode 'securityProblemSelector=status("OPEN"),technology("JAVA"),vulnerabilityType("THIRD_PARTY")' \
  --data-urlencode 'pageSize=500'
```

The response provides information such as:

- Security problem ID.
- CVE identifiers.
- Package name and technology.
- Vulnerability status.
- Risk score and severity.
- Exposure and vulnerable-function usage signals.

Reference: [Vulnerabilities API](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/vulnerabilities/get-vulnerabilities)

## 2. Retrieve Runtime and Topology Context

Use the returned security problem ID to retrieve the full context:

```bash
curl --get \
  "https://${DT_ENVIRONMENT_ID}.live.dynatrace.com/api/v2/securityProblems/${SECURITY_PROBLEM_ID}" \
  -H "Authorization: Api-Token ${DT_API_TOKEN}" \
  --data-urlencode 'from=now-7d' \
  --data-urlencode 'fields=+riskAssessment,+vulnerableComponents,+affectedEntities,+exposedEntities,+reachableDataAssets,+relatedEntities,+relatedAttacks,+entryPoints,+events,+remediationDescription'
```

Important response fields include:

| Field | Value for risk analysis |
|---|---|
| `vulnerableComponents` | Log4j component identity, file information, and affected entities |
| `affectedEntities` | Processes where the vulnerable component is running |
| `relatedEntities.services` | Services connected to the affected processes |
| `relatedEntities.applications` | Frontend applications reaching the services |
| `exposedEntities` | Affected entities exposed to the internet |
| `reachableDataAssets` | Database-connected services reachable from affected entities |
| `entryPoints` | HTTP paths that can potentially reach the vulnerability |
| `relatedAttacks` | Attacks observed against the exposed vulnerability |
| `riskAssessment.vulnerableFunctionUsage` | Whether vulnerable code is actually used |
| `riskAssessment.publicExploit` | Whether a public exploit is available |

Reference: [Vulnerability details API](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/vulnerabilities/get-vulnerability-details)

## 3. Confirm Vulnerable-Function Usage

```bash
curl --get \
  "https://${DT_ENVIRONMENT_ID}.live.dynatrace.com/api/v2/securityProblems/${SECURITY_PROBLEM_ID}/vulnerableFunctions" \
  -H "Authorization: Api-Token ${DT_API_TOKEN}" \
  --data-urlencode 'groupBy=PROCESS_GROUP'
```

The response identifies:

- Java class and function name.
- File path when available.
- Process groups where the function is `IN_USE`.
- Process groups where it is `NOT_IN_USE`.
- Process groups where usage is `NOT_AVAILABLE`.

For Log4Shell, vulnerable JNDI-related functions are more significant than ordinary Log4j logging calls. Calling `Logger.info()` does not prove that the Log4Shell exploit path was executed.

Reference: [Vulnerable functions API](https://docs.dynatrace.com/docs/dynatrace-api/environment-api/application-security/vulnerabilities/get-vulnerable-functions)

## 4. Retrieve Transactions Through Affected Services

Use the service IDs from `relatedEntities.services` to query spans in Grail:

```dql
fetch spans
| filter dt.entity.service == "SERVICE-REPLACE_ME"
| fields timestamp,
         trace.id,
         span.id,
         span.name,
         endpoint.name,
         service.name,
         duration,
         http.request.method,
         http.response.status_code,
         url.path
| sort timestamp desc
| limit 1000
```

This query identifies which endpoints and transactions passed through the affected service.

Reference: [Advanced Tracing Analytics](https://docs.dynatrace.com/docs/observe/application-observability/distributed-tracing/advanced-tracing-analytics)

## 5. Retrieve User-Behavior Context

Use RUM user events to retrieve the user actions associated with backend traces:

```dql
fetch user.events
| filter isNotNull(trace.id)
| fields timestamp,
         trace.id,
         span.id,
         dt.rum.session.id,
         user.identifier,
         frontend.name,
         view.name,
         view.url.path,
         interaction.type,
         ui_element.name,
         user_action.type,
         user_action.requests.count
| sort timestamp desc
```

This provides:

- User session.
- Pseudonymous or configured user identity.
- Frontend application.
- Page or view.
- UI element and interaction type.
- User-action type.
- Backend trace started by the action.

RUM user actions contain `trace.id` and `span.id` when frontend-to-backend trace correlation is active.

References:

- [User-action semantic fields](https://docs.dynatrace.com/docs/semantic-dictionary/model/rum/user-events/user-actions)
- [Analyze user behavior with DQL](https://docs.dynatrace.com/docs/observe/digital-experience/rum/analyze-and-alert/rum-dql-user-behavior)

## 6. Join User Actions with Affected Transactions

The following is a starting query. Field availability should be validated against the target Dynatrace environment's semantic schema.

```dql
fetch user.events
| filter isNotNull(trace.id)
| fields timestamp,
         trace.id,
         dt.rum.session.id,
         user.identifier,
         frontend.name,
         view.name,
         view.url.path,
         interaction.type,
         ui_element.name
| join [
    fetch spans
    | filter dt.entity.service == "SERVICE-REPLACE_ME"
    | fields trace.id,
             service.name,
             endpoint.name,
             span.name,
             duration,
             http.request.method,
             http.response.status_code
  ],
  on: {trace.id}
| fields timestamp,
         trace.id,
         dt.rum.session.id,
         user.identifier,
         frontend.name,
         view.name,
         view.url.path,
         interaction.type,
         ui_element.name,
         right.service.name,
         right.endpoint.name,
         right.span.name,
         right.duration,
         right.http.response.status_code
| sort timestamp desc
```

The resulting relationship is:

```text
User action -> trace -> affected service -> endpoint -> transaction outcome
```

Reference: [DQL correlation and join commands](https://docs.dynatrace.com/docs/platform/grail/dynatrace-query-language/commands/correlation-and-join-commands)

## 7. Execute DQL Through the Grail API

Submit the query using OAuth:

```http
POST https://{environment-id}.apps.dynatrace.com/platform/storage/query/v1/query:execute
Authorization: Bearer {oauth-token}
Content-Type: application/json

{
  "query": "fetch spans | filter dt.entity.service == \"SERVICE-...\" | limit 100"
}
```

If execution is asynchronous, poll using the returned request token:

```http
GET https://{environment-id}.apps.dynatrace.com/platform/storage/query/v1/query:poll?request-token={encoded-token}
Authorization: Bearer {oauth-token}
```

Reference: [Grail Query API flow](https://docs.dynatrace.com/docs/observe/business-observability/bo-events-capturing/bo-events-capturing-external-sources#dql-queries-via-api)

## Recommended ScoutGrid Risk Model

For each vulnerable open-source component, calculate contextual risk using:

- Library loaded at runtime.
- Known CVE and affected version.
- Vulnerable function `IN_USE`.
- Publicly exposed affected service.
- Public exploit availability.
- Reachable data assets.
- Related attack observed.
- Number and frequency of transactions through affected services.
- Number of distinct sessions or users.
- Business-critical endpoints involved.
- Failed or anomalous transaction rate.
- Fix version and remediation availability.

### Suggested Evidence Levels

| Level | Meaning |
|---|---|
| Present | The vulnerable library is loaded in a running process |
| Reachable | User or system transactions reach the affected service |
| In use | Dynatrace reports the vulnerable function as used by the process group |
| Transaction-correlated | Trace-linked telemetry shows a particular transaction invoking the relevant code path |
| Exploited | Dynatrace reports a related attack or confirmed exploit evidence |

## Transaction-Level Evidence Gap

If transaction-level vulnerable-function attribution is required, add one or more of the following:

- Trace-correlated application logs that identify the relevant Log4j/JNDI operation.
- Custom spans around security-sensitive library calls.
- Span attributes identifying component name, version, and operation.
- Dynatrace attack findings correlated to the affected service and trace.
- Application-level business events containing a trace ID and a non-sensitive operation classification.

Avoid sending raw credentials, request bodies, authentication tokens, or sensitive personal data. User identifiers should be pseudonymized or aggregated unless there is a justified, access-controlled investigative requirement.

