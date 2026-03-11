ALTER TABLE public.sync_runs
    ADD COLUMN IF NOT EXISTS metadata_json TEXT;
