BEGIN;

-- A legacy database must be cleaned deliberately before the canonical hostname
-- constraint can be enabled. This migration never deletes or merges Server rows.
DO $$
DECLARE
    invalid_hostname_count BIGINT;
    duplicate_hostname_count BIGINT;
BEGIN
    SELECT COUNT(*)
    INTO invalid_hostname_count
    FROM server
    WHERE hostname IS NULL OR BTRIM(hostname) = '';

    IF invalid_hostname_count > 0 THEN
        RAISE EXCEPTION
            'SERVER_MIGRATION_INVALID_HOSTNAME: % server row(s) have a NULL or blank hostname',
            invalid_hostname_count;
    END IF;

    SELECT COUNT(*)
    INTO duplicate_hostname_count
    FROM (
        SELECT BTRIM(hostname)
        FROM server
        GROUP BY BTRIM(hostname)
        HAVING COUNT(*) > 1
    ) AS duplicate_hostnames;

    IF duplicate_hostname_count > 0 THEN
        RAISE EXCEPTION
            'SERVER_MIGRATION_DUPLICATE_HOSTNAME: % normalized hostname(s) have duplicate rows',
            duplicate_hostname_count;
    END IF;
END
$$;

UPDATE server
SET hostname = BTRIM(hostname)
WHERE hostname IS DISTINCT FROM BTRIM(hostname);

ALTER TABLE server
    ALTER COLUMN hostname SET NOT NULL;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'server'::regclass
          AND conname = 'ck_server_hostname_normalized'
    ) THEN
        ALTER TABLE server
            ADD CONSTRAINT ck_server_hostname_normalized
            CHECK (hostname = BTRIM(hostname) AND hostname <> '');
    END IF;
END
$$;

CREATE UNIQUE INDEX IF NOT EXISTS uq_server_hostname
    ON server (hostname);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conrelid = 'server'::regclass
          AND conname = 'uq_server_hostname'
    ) THEN
        ALTER TABLE server
            ADD CONSTRAINT uq_server_hostname
            UNIQUE USING INDEX uq_server_hostname;
    END IF;
END
$$;

CREATE TABLE IF NOT EXISTS application_server_relation (
    application_id BIGINT NOT NULL REFERENCES application(application_id),
    server_id BIGINT NOT NULL REFERENCES server(server_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_id, server_id)
);

CREATE INDEX IF NOT EXISTS idx_application_server_relation_server_id
    ON application_server_relation (server_id);

COMMIT;
