# Azure agent fixtures

Created on 2026-10-05 in the existing `ravikanukollu-1991-resource/ravikanukollu-1991` Foundry project through Azure MCP. All content is synthetic. Existing agents and model deployments were preserved. No agents or code-interpreter sessions were invoked.

| Agent | Purpose | Tool/data |
| --- | --- | --- |
| noscan-test-prompt-20261005 | Product FAQ | Prompt only |
| noscan-test-retrieval-20261005 | Grounded handbook answers | File search over the populated sample vector store |
| noscan-test-analytics-20261005 | Orders totals and summaries | Code interpreter with the synthetic orders CSV attached |
| noscan-test-function-20261005 | Read-only demo order status | Function declaration; requires a caller implementation of `lookup_demo_order` |

The JSON files contain the prompts, tool definitions, and Azure MCP creation arguments. `created-resources.json` records the actual resource IDs and versions. Replaying an existing definition creates another version; these files are reviewable fixtures, not an automatic startup seed.

The handbook vector store completed indexing and expires after seven days of inactivity. Files/vector stores were created through the documented Foundry REST endpoints because this Azure MCP version exposes agent creation but no file/vector-store creation commands. See [Microsoft's file-search documentation](https://learn.microsoft.com/en-us/azure/foundry/agents/how-to/tools/file-search).

Azure MCP also created the private `mcpagentstorage2/noscan-test-agents-20261005` blob container. Upload was denied by the caller's blob data-plane permissions, so that container is empty; the populated vector store is the working retrieval datastore. No Azure roles or public access settings were changed.

## Local discovery repairs

Workspace `bbb` had no Foundry rollout flags enabled. The Azure connector page now shows both discovery switches and explains when agent collection is disabled. Foundry and classic Foundry discovery were enabled through the authenticated settings UI.

The first enabled run failed because the local backend lacked `APP_AI_SECURITY_IDENTITY_HMAC_KEY`. A random local key was added to the ignored `backend/.env.local`, and the backend was restarted. No prompt plaintext is persisted to inventory; existing HMAC validation remains in place.

The existing local tenants were at V13. V14 was applied to `tenant_default` and `tenant_bbb` through Flyway with history/checksum validation, adding the Agents settings table and indexes. The legacy test runner first stopped on its template drift comparison; the focused migration used the same tenant Flyway configuration as the production bootstrap and preserved existing data.

The adapter now recognizes the current `definition.kind` discriminator and retains successfully discovered agents when another project returns 404. The unrelated `testmcpazure/proj-default` project reports an unreachable or misconfigured Cosmos DB endpoint. Its provider error remains a collection gap rather than being hidden.

## Verification

The authenticated `bbb` Agents page displays nine Azure logical agents, including all four fixtures. Searching for `noscan-test` displays exactly four rows. Definition presence is verified; serving/deployment remains unverified, and the fixtures were not invoked. The custom function is a declaration rather than a hosted function implementation.

The focused backend suite passed 23 tests (Foundry metadata, mixed-project discovery, and Azure management collection). The connector page's three tests, frontend type checking, production build, and `git diff --check` passed. Changes remain uncommitted on `codex/unified-agents-roster`.

The final connector pass completed at 21:13:57 IST on 2026-10-05 with `partial` status and no run-level error. The unrelated project’s provider failure remains reported.
