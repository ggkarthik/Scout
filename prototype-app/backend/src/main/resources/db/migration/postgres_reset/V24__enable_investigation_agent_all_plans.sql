UPDATE platform.plan_entitlements
SET enabled = true,
    updated_at = now()
WHERE entitlement_key = 'ai.investigation_agent';
