import subprocess
import sys
from pathlib import Path


def test_parser_agent_cli_exists_and_handles_missing_input(tmp_path):
    project_root = Path(__file__).parents[1]
    entrypoint = project_root / "parser_agent_main.py"

    assert entrypoint.is_file()

    completed = subprocess.run(
        [
            sys.executable,
            str(entrypoint),
            "--input",
            str(tmp_path / "missing.csv"),
            "--output-dir",
            str(tmp_path / "output"),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode != 0
    assert "Parser Agent V0" in completed.stdout
    assert "Agent status      : FAILED" in completed.stdout
    assert "INPUT_FILE_NOT_FOUND" in completed.stdout
