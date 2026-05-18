CREATE TABLE IF NOT EXISTS public.tenant_support_grants (
    id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    invited_platform_subject character varying(320) NOT NULL,
    reason character varying(2000) NOT NULL,
    scope character varying(512),
    access_mode character varying(32) NOT NULL,
    status character varying(32) NOT NULL,
    granted_by uuid NOT NULL,
    accepted_by uuid,
    revoked_by uuid,
    requested_at timestamp(6) with time zone NOT NULL,
    accepted_at timestamp(6) with time zone,
    expires_at timestamp(6) with time zone NOT NULL,
    revoked_at timestamp(6) with time zone,
    updated_at timestamp(6) with time zone NOT NULL
);

ALTER TABLE ONLY public.tenant_support_grants
    ADD CONSTRAINT tenant_support_grants_pkey PRIMARY KEY (id);

ALTER TABLE ONLY public.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_tenant
    FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

ALTER TABLE ONLY public.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_granted_by
    FOREIGN KEY (granted_by) REFERENCES public.app_users(id);

ALTER TABLE ONLY public.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_accepted_by
    FOREIGN KEY (accepted_by) REFERENCES public.app_users(id);

ALTER TABLE ONLY public.tenant_support_grants
    ADD CONSTRAINT fk_tenant_support_grants_revoked_by
    FOREIGN KEY (revoked_by) REFERENCES public.app_users(id);

CREATE INDEX IF NOT EXISTS idx_tenant_support_grants_tenant_requested
    ON public.tenant_support_grants (tenant_id, requested_at DESC);

CREATE INDEX IF NOT EXISTS idx_tenant_support_grants_subject_status_expires
    ON public.tenant_support_grants (invited_platform_subject, status, expires_at DESC);
