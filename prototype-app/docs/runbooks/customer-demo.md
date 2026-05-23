# Customer Demo Runbook

Last updated: 2026-05-20

## Demo Shape

- Access is invite-only.
- Each approved request provisions a `DEMO` tenant for 7 days.
- Demo tenants can use sample data and limited SBOM ingestion.
- Live ServiceNow, SCCM, AWS Discovery, GitHub SBOM sources, and AI actions are blocked for demo tenants.

## Operator Flow

1. Review requests in Platform Console -> Demo Requests.
2. Approve a qualified request.
3. Copy or send the generated invite URL.
4. Confirm the tenant has `plan_code=DEMO`, an expiration timestamp, and low demo quotas.
5. Use `/api/demo/status` after login to verify capabilities and usage.

## Expiration

The backend runs the demo expiration job hourly by default. Expired active demo tenants are marked
`SUSPENDED`, and the tenant status filter blocks normal tenant APIs with `TENANT_SUSPENDED`.

## Smoke Checks

- Submit a request from `/demo/request`.
- Approve it from `/platform/demo-requests`.
- Open `/invite/<token>` and accept it.
- Log in through the configured hosted IdP.
- Confirm the top bar shows `Demo` and days remaining.
- Confirm `/connect` allows SBOM endpoint ingestion and marks live connectors unavailable.
