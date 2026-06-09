from __future__ import annotations

import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_run_launcher_help_and_wrappers() -> None:
    completed = subprocess.run(
        ["bash", "run.sh", "--help"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
        text=True,
    )

    assert "./run.sh [auto|ui|full]" in completed.stdout
    assert "Modes:" in completed.stdout

    run_full_capacity = (REPO_ROOT / "run_full_capacity.sh").read_text(encoding="utf-8")
    run_full_stack = (REPO_ROOT / "scripts" / "run_full_stack.sh").read_text(encoding="utf-8")

    assert 'exec "$ROOT_DIR/run.sh" full' in run_full_capacity
    assert 'exec "$ROOT_DIR/run.sh" full' in run_full_stack
