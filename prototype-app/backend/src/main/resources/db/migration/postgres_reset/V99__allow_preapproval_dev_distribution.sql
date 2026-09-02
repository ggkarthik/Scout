-- migration-guard: platform-only
-- Correct the distribution trigger for the new pre-approval DEV stage.

CREATE OR REPLACE FUNCTION platform.require_ai_grid_distribution_approval()
RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE pinned platform.ai_grid_policy_versions%ROWTYPE;
BEGIN
    IF NEW.rollout_stage = 'DEV' THEN
        IF NEW.pinned_version IS NULL THEN RAISE EXCEPTION 'Dev distribution requires a pinned version'; END IF;
        RETURN NEW;
    END IF;
    IF NEW.available OR NEW.rollout_stage IN ('GENERAL_AVAILABILITY','CANARY') OR NEW.pinned_version IS NOT NULL THEN
        IF NEW.pinned_version IS NULL THEN RAISE EXCEPTION 'Active distribution requires a pinned version'; END IF;
        SELECT * INTO pinned FROM platform.ai_grid_policy_versions
         WHERE policy_id = NEW.policy_id AND version = NEW.pinned_version;
        IF FOUND AND pinned.package_digest IS NULL THEN RETURN NEW; END IF;
        IF NOT FOUND OR pinned.lifecycle NOT IN ('PUBLISHED','CANARY','DEPRECATED')
           OR NOT platform.ai_grid_approved_decision_matches(NEW.policy_id, NEW.pinned_version,
                                                              NEW.approved_package_digest, NEW.release_decision_id)
           OR pinned.package_digest <> NEW.approved_package_digest THEN
            RAISE EXCEPTION 'Distribution requires an exact unrevoked approval binding';
        END IF;
    END IF;
    RETURN NEW;
END $$;
