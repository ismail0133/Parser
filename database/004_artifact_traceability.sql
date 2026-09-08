BEGIN;

ALTER TABLE artifact
    ADD COLUMN IF NOT EXISTS pipeline_run_id UUID,
    ADD COLUMN IF NOT EXISTS agent_run_id BIGINT,
    ADD COLUMN IF NOT EXISTS row_count BIGINT;

-- The pair is required by the composite Artifact foreign key. agent_run_id is
-- already globally unique, so this constraint does not change Agent semantics.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'agent_run'::regclass
          AND conname = 'uq_agent_run_pipeline_agent_run'
    ) THEN
        ALTER TABLE agent_run
            ADD CONSTRAINT uq_agent_run_pipeline_agent_run
            UNIQUE (pipeline_run_id, agent_run_id);
    END IF;
END
$$;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'fk_artifact_pipeline_run'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT fk_artifact_pipeline_run
            FOREIGN KEY (pipeline_run_id)
            REFERENCES pipeline_run(pipeline_run_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'fk_artifact_agent_run'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT fk_artifact_agent_run
            FOREIGN KEY (agent_run_id)
            REFERENCES agent_run(agent_run_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'fk_artifact_agent_run_pipeline'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT fk_artifact_agent_run_pipeline
            FOREIGN KEY (pipeline_run_id, agent_run_id)
            REFERENCES agent_run(pipeline_run_id, agent_run_id);
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'ck_artifact_row_count_non_negative'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT ck_artifact_row_count_non_negative
            CHECK (row_count >= 0);
    END IF;

    -- NOT VALID preserves untraceable legacy rows while enforcing the rule for
    -- every new or updated Artifact. Legacy rows must be backfilled explicitly.
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'ck_artifact_pipeline_run_required'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT ck_artifact_pipeline_run_required
            CHECK (pipeline_run_id IS NOT NULL) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'ck_artifact_required_metadata'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT ck_artifact_required_metadata
            CHECK (
                artifact_type IS NOT NULL
                AND filename IS NOT NULL
                AND storage_path IS NOT NULL
                AND sha256 IS NOT NULL
            ) NOT VALID;
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'artifact'::regclass
          AND conname = 'ck_artifact_sha256_format'
    ) THEN
        ALTER TABLE artifact
            ADD CONSTRAINT ck_artifact_sha256_format
            CHECK (sha256 ~ '^[0-9a-f]{64}$') NOT VALID;
    END IF;
END
$$;

-- On a fresh/empty Artifact table, expose the requirement as a real NOT NULL
-- column immediately. Legacy NULL rows remain untouched and are protected by
-- the NOT VALID check above until an explicit provenance backfill is possible.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM artifact WHERE pipeline_run_id IS NULL) THEN
        ALTER TABLE artifact
            ALTER COLUMN pipeline_run_id SET NOT NULL;
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS idx_artifact_pipeline_run_id
    ON artifact (pipeline_run_id);
CREATE INDEX IF NOT EXISTS idx_artifact_agent_run_id
    ON artifact (agent_run_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_artifact_run_type_path
    ON artifact (pipeline_run_id, artifact_type, storage_path);

COMMIT;
