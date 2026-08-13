from pathlib import Path
from typing import Any, Callable, TypedDict

from langgraph.graph import END, START, StateGraph

from src.models.parser_result import ParserResult
from src.tools.parser_tools import analyze_parser_kri_warnings, run_parser


class ParserAgentState(TypedDict, total=False):
    input_file: str
    output_dir: str
    parser_result: ParserResult
    agent_status: str
    next_action: str
    warnings_summary: dict[str, Any]
    kri_analysis: dict[str, Any] | None
    application_enrichment_status: str
    artifacts: dict[str, str]
    dependencies: dict[str, str]
    error_message: str | None
    reason: str | None


ParserRunner = Callable[[str, str], dict[str, Any]]
KriAnalyzer = Callable[[str, dict[str, str], str], dict[str, Any] | None]


def build_parser_graph(
    parser_runner: ParserRunner = run_parser,
    kri_analyzer: KriAnalyzer = analyze_parser_kri_warnings,
):
    def validate_input(state: ParserAgentState) -> dict[str, Any]:
        path = Path(state["input_file"])
        if not path.is_file():
            return {
                "agent_status": "FAILED", "next_action": "STOP",
                "reason": "INPUT_FILE_NOT_FOUND",
                "error_message": f"Input file not found: {path}",
            }
        try:
            with path.open("rb") as stream:
                stream.read(1)
        except OSError as exc:
            return {
                "agent_status": "FAILED", "next_action": "STOP",
                "reason": "INPUT_FILE_NOT_READABLE", "error_message": str(exc),
            }
        return {}

    def route_after_validation(state: ParserAgentState) -> str:
        return "finalize_failed" if state.get("agent_status") == "FAILED" else "run_parser"

    def run_parser_node(state: ParserAgentState) -> dict[str, Any]:
        try:
            return parser_runner(state["input_file"], state["output_dir"])
        except Exception as exc:
            return {
                "agent_status": "FAILED", "next_action": "STOP",
                "reason": "PARSER_EXECUTION_FAILED", "error_message": str(exc),
            }

    def check_result(state: ParserAgentState) -> dict[str, Any]:
        result = state.get("parser_result")
        if result is None:
            return {}
        if result.status in {"FAILED", "FAILED_AFTER_RETRIES"} or result.errors > 0:
            return {"agent_status": "FAILED", "next_action": "STOP"}
        if result.warnings > 0:
            return {
                "agent_status": "SUCCESS_WITH_WARNINGS", "next_action": "CONTINUE",
                "warnings_summary": {"total": result.warnings},
                "application_enrichment_status": result.application_enrichment_status,
            }
        return {
            "agent_status": "SUCCESS", "next_action": "CONTINUE",
            "warnings_summary": {"total": 0},
            "application_enrichment_status": result.application_enrichment_status,
        }

    def route_after_check(state: ParserAgentState) -> str:
        if state.get("agent_status") == "FAILED":
            return "finalize_failed"
        if state.get("agent_status") == "SUCCESS_WITH_WARNINGS":
            return "analyze_warnings"
        return "finalize"

    def analyze_warnings(state: ParserAgentState) -> dict[str, Any]:
        try:
            analysis = kri_analyzer(
                state["input_file"], state.get("artifacts", {}), state["output_dir"]
            )
            artifacts = dict(state.get("artifacts", {}))
            if analysis:
                if analysis.get("json_report"):
                    artifacts["kri_analysis_json"] = analysis["json_report"]
                if analysis.get("markdown_report"):
                    artifacts["kri_analysis_markdown"] = analysis["markdown_report"]
            return {"kri_analysis": analysis, "artifacts": artifacts}
        except Exception as exc:
            return {
                "agent_status": "FAILED", "next_action": "STOP",
                "reason": "WARNING_ANALYSIS_FAILED", "error_message": str(exc),
            }

    def finalize(state: ParserAgentState) -> dict[str, Any]:
        return {
            "dependencies": {
                "cib_apm": "WAITING_FOR_SOURCE",
                "postgresql": "NOT_CONFIGURED",
                "llm_api": "NOT_CONFIGURED",
            }
        }

    def finalize_failed(state: ParserAgentState) -> dict[str, Any]:
        return {
            "agent_status": "FAILED", "next_action": "STOP",
            "dependencies": {
                "cib_apm": "WAITING_FOR_SOURCE",
                "postgresql": "NOT_CONFIGURED",
                "llm_api": "NOT_CONFIGURED",
            },
        }

    graph = StateGraph(ParserAgentState)
    graph.add_node("validate_input", validate_input)
    graph.add_node("run_parser", run_parser_node)
    graph.add_node("check_result", check_result)
    graph.add_node("analyze_warnings", analyze_warnings)
    graph.add_node("finalize", finalize)
    graph.add_node("finalize_failed", finalize_failed)
    graph.add_edge(START, "validate_input")
    graph.add_conditional_edges("validate_input", route_after_validation)
    graph.add_edge("run_parser", "check_result")
    graph.add_conditional_edges("check_result", route_after_check)
    graph.add_edge("analyze_warnings", "finalize")
    graph.add_edge("finalize", END)
    graph.add_edge("finalize_failed", END)
    return graph.compile()
