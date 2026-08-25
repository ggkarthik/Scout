-- migration-guard: platform-only
ALTER TABLE platform.ai_grid_policy_versions
    ADD COLUMN IF NOT EXISTS release_family varchar(128),
    ADD COLUMN IF NOT EXISTS release_wave varchar(128);

UPDATE platform.ai_grid_policy_versions
   SET release_family = coalesce(release_family, 'AGCF_PHASE_1'),
       release_wave = coalesce(release_wave, 'PHASE_1')
 WHERE policy_id LIKE 'AGCF-%';

ALTER TABLE platform.ai_grid_policy_versions
    ADD CONSTRAINT ai_grid_policy_release_family_check
        CHECK (release_family IS NULL OR length(trim(release_family)) > 0),
    ADD CONSTRAINT ai_grid_policy_release_wave_check
        CHECK (release_wave IS NULL OR length(trim(release_wave)) > 0);
