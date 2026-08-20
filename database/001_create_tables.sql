BEGIN;

CREATE TABLE application (
    application_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    auid TEXT UNIQUE,
    trigram TEXT,
    application_name TEXT,
    application_status TEXT,
    priority INTEGER,
    appsec TEXT,
    appsec_num INTEGER,
    vital TEXT,
    vital_num INTEGER,
    cis BOOLEAN,
    strategic BOOLEAN,
    ciat_confidentiality TEXT,
    ciat_integrity TEXT,
    ciat_availability TEXT,
    ciat_traceability TEXT,
    ciat_num INTEGER,
    continuity_level TEXT,
    business_line TEXT,
    sub_business_line TEXT,
    application_manager TEXT,
    domain_manager TEXT,
    production_manager TEXT,
    production_domain_manager TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE server (
    server_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hostname TEXT,
    operating_system TEXT,
    os_name TEXT,
    os_version TEXT,
    environment TEXT,
    environment_detail TEXT,
    sensitive BOOLEAN,
    authenticated_scan BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vulnerability (
    vulnerability_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_code TEXT,
    title TEXT,
    description TEXT,
    severity_level TEXT,
    cvss_score NUMERIC,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE pipeline_run (
    pipeline_run_id UUID PRIMARY KEY,
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    run_status TEXT,
    source_filename TEXT,
    input_rows BIGINT CHECK (input_rows >= 0),
    output_findings BIGINT CHECK (output_findings >= 0),
    error_count BIGINT CHECK (error_count >= 0),
    warning_count BIGINT CHECK (warning_count >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE agent (
    agent_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_code TEXT NOT NULL,
    agent_name TEXT,
    execution_order INTEGER,
    active BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE agent_run (
    agent_run_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pipeline_run_id UUID NOT NULL REFERENCES pipeline_run(pipeline_run_id),
    agent_id BIGINT NOT NULL REFERENCES agent(agent_id),
    attempt_no INTEGER NOT NULL CHECK (attempt_no >= 1),
    started_at TIMESTAMPTZ,
    ended_at TIMESTAMPTZ,
    run_status TEXT,
    feedback_type TEXT,
    feedback_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_agent_run_attempt UNIQUE (pipeline_run_id, agent_id, attempt_no)
);

CREATE TABLE finding (
    finding_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pipeline_run_id UUID NOT NULL REFERENCES pipeline_run(pipeline_run_id),
    application_id BIGINT REFERENCES application(application_id),
    server_id BIGINT REFERENCES server(server_id),
    vulnerability_id BIGINT REFERENCES vulnerability(vulnerability_id),
    source_unique_id TEXT,
    remediation_id TEXT,
    application_auid TEXT,
    as_of_date DATE,
    absolute_first_found_date DATE,
    last_found_date DATE,
    age_days INTEGER CHECK (age_days >= 0),
    sla_days INTEGER CHECK (sla_days >= 0),
    overdue BOOLEAN,
    priority INTEGER,
    affected_component TEXT,
    product TEXT,
    extract_path TEXT,
    severity_level TEXT,
    business_line TEXT,
    proposed_action TEXT,
    ownership TEXT,
    false_positive BOOLEAN,
    false_positive_to_confirm BOOLEAN,
    eta DATE,
    strategy_type TEXT,
    strategy_description TEXT,
    solution_links TEXT,
    source_payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE anomaly (
    anomaly_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    pipeline_run_id UUID REFERENCES pipeline_run(pipeline_run_id),
    agent_run_id BIGINT REFERENCES agent_run(agent_run_id),
    finding_id BIGINT REFERENCES finding(finding_id),
    anomaly_level TEXT,
    code TEXT,
    message TEXT,
    details JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE artifact (
    artifact_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    artifact_type TEXT,
    filename TEXT,
    storage_path TEXT,
    sha256 TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

COMMIT;
