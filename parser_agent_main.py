import argparse

from src.agents.parser_agent import render_execution_summary, run_parser_agent


def main() -> int:
    cli = argparse.ArgumentParser(description="Run Parser Agent V0")
    cli.add_argument("--input", required=True, help="Path to RAW Finding CSV")
    cli.add_argument("--output-dir", default="output", help="Output directory")
    args = cli.parse_args()
    result = run_parser_agent(args.input, args.output_dir)
    print("Parser Agent V0")
    print(render_execution_summary(result))
    if result.error_message:
        print(f"Reason            : {result.reason} - {result.error_message}")
    return 1 if result.status == "FAILED" else 0


if __name__ == "__main__":
    raise SystemExit(main())
