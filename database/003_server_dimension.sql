BEGIN;

-- Create the relation table before cleanup so a migration retry also protects
-- legacy Server rows already referenced by an Application-Server relation.
CREATE TABLE IF NOT EXISTS application_server_relation (
    application_id BIGINT NOT NULL REFERENCES application(application_id),
    server_id BIGINT NOT NULL REFERENCES server(server_id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (application_id, server_id)
);

-- Preflight diagnostic. psql displays these rows before any cleanup or blocking
-- exception. A NULL hostname and a whitespace-only hostname are both invalid.
SELECT
    s.server_id,
    s.hostname,
    COUNT(DISTINCT f.finding_id) AS linked_findings,
    s.created_at,
    s.updated_at
FROM server AS s
LEFT JOIN finding AS f
    ON f.server_id = s.server_id
WHERE s.hostname IS NULL OR BTRIM(s.hostname) = ''
GROUP BY s.server_id, s.hostname, s.created_at, s.updated_at
ORDER BY s.server_id;

-- Delete only invalid Server rows that carry no Finding and no
-- Application-Server relation. If a later validation blocks this transaction,
-- PostgreSQL rolls these deletes back with the rest of the migration.
WITH deleted_invalid_servers AS (
    DELETE FROM server AS s
    WHERE (s.hostname IS NULL OR BTRIM(s.hostname) = '')
      AND NOT EXISTS (
          SELECT 1
          FROM finding AS f
          WHERE f.server_id = s.server_id
      )
      AND NOT EXISTS (
          SELECT 1
          FROM application_server_relation AS relation
          WHERE relation.server_id = s.server_id
      )
    RETURNING s.server_id, s.hostname, s.created_at, s.updated_at
)
SELECT
    server_id,
    hostname,
    0::BIGINT AS linked_findings,
    created_at,
    updated_at
FROM deleted_invalid_servers
ORDER BY server_id;

-- Any invalid row still present is referenced and must be resolved explicitly.
-- The migration never detaches Findings and never invents a placeholder hostname.
DO $$
DECLARE
    invalid_hostname_details TEXT;
BEGIN
    SELECT STRING_AGG(
        FORMAT(
            'server_id=%s (linked_findings=%s, linked_application_relations=%s)',
            invalid_server.server_id,
            invalid_server.linked_findings,
            invalid_server.linked_application_relations
        ),
        '; ' ORDER BY invalid_server.server_id
    )
    INTO invalid_hostname_details
    FROM (
        SELECT
            s.server_id,
            COUNT(DISTINCT f.finding_id) AS linked_findings,
            COUNT(DISTINCT relation.application_id) AS linked_application_relations
        FROM server AS s
        LEFT JOIN finding AS f
            ON f.server_id = s.server_id
        LEFT JOIN application_server_relation AS relation
            ON relation.server_id = s.server_id
        WHERE s.hostname IS NULL OR BTRIM(s.hostname) = ''
        GROUP BY s.server_id
    ) AS invalid_server;

    IF invalid_hostname_details IS NOT NULL THEN
        RAISE EXCEPTION
            'SERVER_MIGRATION_INVALID_HOSTNAME_REFERENCED: migration stopped; %',
            invalid_hostname_details
            USING HINT =
                'Assign a verified hostname or explicitly detach the listed references, then rerun migration 003.';
    END IF;
END
$$;

-- Duplicate diagnostic after BTRIM, at the same case-sensitive grain as the
-- canonical Server identity. Duplicate rows are never merged automatically.
WITH duplicate_hostnames AS (
    SELECT BTRIM(hostname) AS normalized_hostname
    FROM server
    GROUP BY BTRIM(hostname)
    HAVING COUNT(*) > 1
)
SELECT
    s.server_id,
    s.hostname,
    COUNT(DISTINCT f.finding_id) AS linked_findings,
    s.created_at,
    s.updated_at
FROM server AS s
JOIN duplicate_hostnames AS duplicate
    ON duplicate.normalized_hostname = BTRIM(s.hostname)
LEFT JOIN finding AS f
    ON f.server_id = s.server_id
GROUP BY s.server_id, s.hostname, s.created_at, s.updated_at
ORDER BY BTRIM(s.hostname), s.server_id;

DO $$
DECLARE
    duplicate_hostname_details TEXT;
BEGIN
    SELECT STRING_AGG(
        FORMAT(
            'hostname=%L (server_ids=[%s])',
            duplicate.normalized_hostname,
            duplicate.server_ids
        ),
        '; ' ORDER BY duplicate.normalized_hostname
    )
    INTO duplicate_hostname_details
    FROM (
        SELECT
            BTRIM(hostname) AS normalized_hostname,
            STRING_AGG(server_id::TEXT, ', ' ORDER BY server_id) AS server_ids
        FROM server
        GROUP BY BTRIM(hostname)
        HAVING COUNT(*) > 1
    ) AS duplicate;

    IF duplicate_hostname_details IS NOT NULL THEN
        RAISE EXCEPTION
            'SERVER_MIGRATION_DUPLICATE_HOSTNAME: migration stopped; %',
            duplicate_hostname_details
            USING HINT =
                'Review the listed Server rows and their Finding references, merge them explicitly, then rerun migration 003.';
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

CREATE INDEX IF NOT EXISTS idx_application_server_relation_server_id
    ON application_server_relation (server_id);

COMMIT;
