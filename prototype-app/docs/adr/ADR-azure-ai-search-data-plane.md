# ADR: Azure AI Search data-plane discovery

## Status

Control-plane discovery approved. Data-plane discovery is conditional.

## Decision

The pilot must not grant Search Service Contributor. Data-plane discovery is
enabled only after a definition-only custom role proves that NoScan can list
index, indexer, skillset, and data-source definitions while being denied:

- admin-key and query-key retrieval;
- document reads;
- create, update, delete, run, reset, and indexing operations;
- role-assignment and authentication-setting changes.

If Azure cannot express and enforce that role, the pilot ships Search
control-plane inventory only. A data-plane denial marks only the corresponding
scope `PARTIAL`; it cannot deactivate Search services or resolve findings based
on control-plane facts.

Search Service Contributor requires a separate security ADR after the pilot.
