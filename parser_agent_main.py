import argparse

from src.agents.parser_agent import run_parser_agent


def main() -> int:
    cli = argparse.ArgumentParser(description="Run Parser Agent V0")
    cli.add_argument("--input", required=True, help="Path to RAW Finding CSV")
    cli.add_argument("--output-dir", default="output", help="Output directory")
    args = cli.parse_args()
    result = run_parser_agent(args.input, args.output_dir)
    parser = result.parser
    print("Parser Agent V0")
    print("------------------------------")
    print(f"Input             : {result.input.rows}")
    print(f"Output            : {parser.output_findings if parser else 0}")
    print(f"Parser status     : {parser.status if parser else 'NOT_RUN'}")
    print(f"Agent status      : {result.status}")
    print(f"Errors            : {parser.errors if parser else 0}")
    print(f"Warnings          : {parser.warnings if parser else 0}")
    print(f"KRI mismatches    : {result.kri.mismatches}")
    print(f"Application       : {result.application_enrichment['status']}")
    print(f"LLM               : {result.llm_status}")
    print(f"PostgreSQL        : {result.dependencies['postgresql']}")
    print(f"Next action       : {result.next_action}")
    print("------------------------------")
    if result.error_message:
        print(f"Reason            : {result.reason} - {result.error_message}")
    return 1 if result.status == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
