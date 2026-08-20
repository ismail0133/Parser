BEGIN;

-- The UNIQUE constraint on application.auid already provides its B-tree index.
CREATE INDEX idx_server_hostname ON server (hostname);
CREATE UNIQUE INDEX uq_vulnerability_cve_code_not_null
    ON vulnerability (cve_code) WHERE cve_code IS NOT NULL;
CREATE INDEX idx_finding_application_id ON finding (application_id);
CREATE INDEX idx_finding_server_id ON finding (server_id);
CREATE INDEX idx_finding_vulnerability_id ON finding (vulnerability_id);
CREATE INDEX idx_finding_absolute_first_found_date ON finding (absolute_first_found_date);
CREATE INDEX idx_agent_run_attempt
    ON agent_run (pipeline_run_id, agent_id, attempt_no);

COMMIT;
