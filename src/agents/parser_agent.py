import json
from datetime import datetime
from pathlib import Path
from typing import Any

from src.models.parser_agent_result import (
    AgentInput,
    AgentKriSummary,
    AgentParserSummary,
    ParserAgentResult,
)
from src.reporting.finding_analysis import OPEN_POINTS
from src.workflow.parser_graph import build_parser_graph


def _open_point_names() -> list[str]:
    return [item["field"] for item in OPEN_POINTS]


def _load_external_enrichment_report(output_dir: str | Path) -> dict[str, Any]:
    report_path = Path(output_dir) / "application_enrichment_report.json"
    if not report_path.is_file():
        return {"status": "NOT_AVAILABLE"}
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"status": "NOT_AVAILABLE"}
    return report if isinstance(report, dict) else {"status": "NOT_AVAILABLE"}


def render_execution_summary(result: ParserAgentResult) -> str:
    parser = result.parser
    enrichment = result.external_application_enrichment
    enrichment_available = enrichment.get("status") != "NOT_AVAILABLE"

    def value(name: str, default: Any = "NOT_AVAILABLE") -> Any:
        return enrichment.get(name, default) if enrichment_available else default

    input_equals_output = value("input_equals_output")
    same_count = (
        parser is not None
        and value("total_findings") == parser.output_findings
        and value("output_findings") == parser.output_findings
    )
    if input_equals_output is True and same_count:
        data_loss = "NO"
    elif enrichment_available and (input_equals_output is False or not same_count):
        data_loss = "YES"
    else:
        data_loss = "NOT_AVAILABLE"
    pipeline_output = value(
        "output_findings", parser.output_findings if parser else "NOT_AVAILABLE"
    )
    match_rate = value("match_rate")
    match_rate_display = f"{match_rate}%" if isinstance(match_rate, (int, float)) else match_rate
    integrity_display = (
        "YES" if input_equals_output is True
        else "NO" if input_equals_output is False
        else "NOT_AVAILABLE"
    )
    postgres_status = result.dependencies.get("postgresql", "NOT_AVAILABLE")
    return f"""========================================
PIPELINE EXECUTION SUMMARY
========================================

PARSER
------
Status              : {parser.status if parser else 'NOT_RUN'}
Agent status      : {result.status}
Total findings      : {parser.output_findings if parser else 0}
Warnings            : {parser.warnings if parser else 0}
Errors              : {parser.errors if parser else 0}
KRI mismatches      : {result.kri.mismatches}

APPLICATION ENRICHMENT (EXTERNAL)
---------------------------------
Status              : {value('status')}
Findings with AUID  : {value('findings_with_auid')}
Findings without AUID: {value('findings_without_auid')}
Matched findings    : {value('matched_findings')}
Unmatched findings  : {value('unmatched_findings')}
Enriched findings   : {value('enriched_findings')}
Match rate          : {match_rate_display}
Application conflicts: {value('application_conflicts')}
Field conflicts     : {value('field_conflicts')}
Input = Output      : {integrity_display}

POSTGRESQL
----------
Status              : {postgres_status}

GLOBAL
------
Parser status       : {parser.status if parser else 'NOT_RUN'}
Data loss           : {data_loss}
Pipeline output     : {pipeline_output} findings"""


def _render_report(result: ParserAgentResult) -> str:
    parser = result.parser
    artifacts = "\n".join(f"- `{name}`: `{path}`" for name, path in result.artifacts.items()) or "- None"
    open_points = "\n".join(f"- {item}" for item in result.open_points) or "- None"
    return f"""# Parser Agent V0

| Metric | Value |
|---|---|
| Status | {result.status} |
| Input | {result.input.file} ({result.input.rows} rows) |
| Output | {parser.output_findings if parser else 0} findings |
| Errors | {parser.errors if parser else 0} |
| Warnings | {parser.warnings if parser else 0} |
| Retries | {parser.retry_count if parser else 0} / {parser.max_attempts if parser else 3} |
| KRI mismatches | {result.kri.mismatches} |
| LLM | {result.llm_status} |
| PostgreSQL | {result.dependencies['postgresql']} |
| Persistence | {result.persistence_status} |
| Next action | {result.next_action} |

## Dependencies

```json
{json.dumps(result.dependencies, ensure_ascii=False, indent=2)}
```

## TO_VALIDATE

{open_points}

## Artifacts

{artifacts}

## Pipeline execution summary

```text
{render_execution_summary(result)}
```
"""


def _build_result(state: dict[str, Any], input_file: str) -> ParserAgentResult:
    parser_result = state.get("parser_result")
    kri_analysis = state.get("kri_analysis") or {}
    distribution = kri_analysis.get("warning_distribution", {})
    classification = kri_analysis.get("classification")
    parser_summary = None
    parser_kri = {}
    input_rows = 0
    application_status = state.get("application_enrichment_status", "SKIPPED_NO_SOURCE")
    open_points = _open_point_names()
    if parser_result is not None:
        input_rows = parser_result.input_rows
        application_status = parser_result.application_enrichment_status
        open_points = [item["field"] for item in parser_result.open_points]
        parser_summary = AgentParserSummary(
            status=parser_result.status,
            output_findings=parser_result.output_findings,
            errors=parser_result.errors,
            warnings=parser_result.warnings,
            retry_count=parser_result.retry_count,
            max_attempts=parser_result.max_attempts,
        )
        parser_kri = parser_result.kri_ras9.get("aggregate", {})
    return ParserAgentResult(
        status=state.get("agent_status", "FAILED"),
        input=AgentInput(file=input_file, rows=input_rows),
        parser=parser_summary,
        kri=AgentKriSummary(
            mismatches=kri_analysis.get("server_level_mismatches", 0),
            classification=classification,
            distribution=distribution,
            automatically_correctable=kri_analysis.get("actually_correctable", 0),
            percentage=kri_analysis.get("kri_percentage", parser_kri.get("percentage")),
            business_target_met=kri_analysis.get(
                "business_target_met", parser_kri.get("business_target_met")
            ),
            source_inconsistencies=kri_analysis.get("source_inconsistencies", 0),
        ),
        application_enrichment={"status": application_status},
        dependencies=state.get("dependencies", {
            "cib_apm": "WAITING_FOR_SOURCE", "postgresql": "NOT_CONFIGURED",
            "llm_api": "NOT_CONFIGURED",
        }),
        requires_business_validation=bool(open_points),
        open_points=open_points,
        artifacts=state.get("artifacts", {}),
        next_action=state.get("next_action", "STOP"),
        reason=state.get("reason"),
        error_message=state.get("error_message"),
    )


def run_parser_agent(
    input_file: str,
    output_dir: str = "output",
    *,
    graph=None,
) -> ParserAgentResult:
    """Run Parser Agent V0 without an LLM and persist its Orchestrator contract."""
    workflow = graph or build_parser_graph()
    state = workflow.invoke({"input_file": input_file, "output_dir": output_dir})
    result = _build_result(state, input_file)
    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)
    result.external_application_enrichment = _load_external_enrichment_report(destination)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = destination / f"PARSER-Agent_Result-{timestamp}.json"
    markdown_path = destination / f"PARSER-Agent_Report-{timestamp}.md"
    result.artifacts.update({
        "agent_result": str(json_path.resolve()),
        "agent_report": str(markdown_path.resolve()),
    })
    json_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    markdown_path.write_text(_render_report(result), encoding="utf-8")
    return result
