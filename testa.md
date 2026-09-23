SELECT
    a.auid,
    s.hostname,
    v.cve_code,
    v.cvss_score,
    f.severity_level,
    f.affected_component,
    f.age_days,
    f.sla_days,
    f.overdue,
    f.proposed_action,
    f.strategy_description

FROM finding AS f

JOIN application AS a
    ON a.application_id = f.application_id

LEFT JOIN server AS s
    ON s.server_id = f.server_id

LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id

WHERE a.auid IN ('AP02876', 'AP43116')
  AND f.pipeline_run_id = 'TON_PIPELINE_RUN_ID'::uuid
  AND LOWER(f.severity_level) IN ('critical', 'very high')
  AND f.false_positive IS NOT TRUE

ORDER BY
    f.overdue DESC,
    v.cvss_score DESC NULLS LAST;






    SELECT
    a.auid,
    a.application_name,

    s.hostname,
    s.environment,
    s.sensitive,
    s.authenticated_scan,

    v.cve_code,
    v.title AS vulnerability_title,
    v.cvss_score,

    f.severity_level,
    f.affected_component,

    f.age_days,
    f.sla_days,
    f.overdue,
    f.false_positive,

    f.remediation_id,
    f.proposed_action,
    f.strategy_type,
    f.strategy_description,
    f.solution_links

FROM finding AS f

LEFT JOIN application AS a
    ON a.application_id = f.application_id

LEFT JOIN server AS s
    ON s.server_id = f.server_id

LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id

WHERE a.auid IN ('AP02876', 'AP43116')
  AND f.pipeline_run_id = 'TON_PIPELINE_RUN_ID'::uuid

ORDER BY
    CASE LOWER(f.severity_level)
        WHEN 'critical' THEN 1
        WHEN 'very high' THEN 2
        WHEN 'high' THEN 3
        WHEN 'medium' THEN 4
        WHEN 'low' THEN 5
        ELSE 6
    END,
    v.cvss_score DESC NULLS LAST,
    f.overdue DESC;





    SELECT
    a.auid,
    a.application_name,
    COUNT(f.finding_id) AS total_findings,

    COUNT(*) FILTER (
        WHERE LOWER(f.severity_level) = 'critical'
    ) AS critical,

    COUNT(*) FILTER (
        WHERE LOWER(f.severity_level) = 'very high'
    ) AS very_high,

    COUNT(*) FILTER (
        WHERE LOWER(f.severity_level) = 'high'
    ) AS high,

    COUNT(*) FILTER (
        WHERE f.overdue IS TRUE
    ) AS overdue_findings,

    COUNT(DISTINCT f.server_id) AS affected_servers,

    COUNT(DISTINCT f.vulnerability_id) AS distinct_vulnerabilities

FROM finding AS f
JOIN application AS a
    ON a.application_id = f.application_id

WHERE a.auid IN ('AP02876', 'AP43116')
  AND f.pipeline_run_id = 'TON_PIPELINE_RUN_ID'::uuid

GROUP BY
    a.auid,
    a.application_name

ORDER BY a.auid;




SELECT
    a.auid,
    s.hostname,
    v.cve_code,
    v.cvss_score,
    f.severity_level,
    f.affected_component,
    f.age_days,
    f.sla_days,
    f.overdue,
    f.false_positive,
    f.proposed_action,
    f.strategy_description
FROM finding AS f
JOIN application AS a
    ON a.application_id = f.application_id
JOIN server AS s
    ON s.server_id = f.server_id
LEFT JOIN vulnerability AS v
    ON v.vulnerability_id = f.vulnerability_id
WHERE a.auid IN ('AP02876', 'AP43116')
  AND s.sensitive IS TRUE
  AND s.authenticated_scan IS TRUE
  AND f.overdue IS TRUE
  AND LOWER(f.severity_level) IN ('critical', 'very high')
  AND f.false_positive IS NOT TRUE
ORDER BY
    a.auid,
    v.cvss_score DESC NULLS LAST,
    s.hostname;



    SELECT DISTINCT
    a.auid,
    a.application_name,
    s.hostname,
    s.environment,
    s.os_name,
    s.os_version
FROM finding AS f
JOIN application AS a
    ON a.application_id = f.application_id
JOIN server AS s
    ON s.server_id = f.server_id
ORDER BY a.auid, s.hostname
LIMIT 50;