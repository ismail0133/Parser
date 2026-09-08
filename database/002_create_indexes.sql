BEGIN;

-- The UNIQUE constraints on application.auid and server.hostname already provide
-- their B-tree indexes.
CREATE INDEX idx_application_server_relation_server_id
    ON application_server_relation (server_id);
CREATE UNIQUE INDEX uq_vulnerability_cve_code_not_null
    ON vulnerability (cve_code) WHERE cve_code IS NOT NULL;
CREATE INDEX idx_finding_application_id ON finding (application_id);
CREATE INDEX idx_finding_server_id ON finding (server_id);
CREATE INDEX idx_finding_vulnerability_id ON finding (vulnerability_id);
CREATE INDEX idx_finding_absolute_first_found_date ON finding (absolute_first_found_date);
CREATE INDEX idx_agent_run_attempt
    ON agent_run (pipeline_run_id, agent_id, attempt_no);
CREATE INDEX idx_artifact_pipeline_run_id ON artifact (pipeline_run_id);
CREATE INDEX idx_artifact_agent_run_id ON artifact (agent_run_id);

COMMIT;
