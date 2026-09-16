"""Wrapper for holehe (check which sites an email is registered on)."""

from __future__ import annotations

import csv
import time
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "holehe"


def run(email: str, out_dir: Path, only_used: bool = True, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("holehe")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    before = {p.name for p in tool_dir.glob("holehe_*_results.csv")}

    cmd = [binary, email, "--no-color", "--no-clear", "--csv"]
    if only_used:
        cmd.append("--only-used")
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    # holehe names its CSV holehe_<timestamp>_<email>_results.csv; timestamp is
    # generated internally so poll briefly for the new file rather than guessing it.
    csv_path = None
    for _ in range(10):
        matches = [p for p in tool_dir.glob("holehe_*_results.csv") if p.name not in before]
        if matches:
            csv_path = matches[0]
            break
        time.sleep(0.2)

    if csv_path and csv_path.exists():
        # holehe's own `--csv` success path calls exit("All results have been
        # exported to ...") which Python turns into a non-zero exit code; the
        # CSV being present is the real signal that the run succeeded.
        result.returncode = 0
        result.output_files.append(csv_path)
        try:
            with csv_path.open(newline="") as fh:
                rows = list(csv.DictReader(fh))
            used = sum(1 for r in rows if str(r.get("exists", "")).lower() == "true")
            result.summary = f"used on {used}/{len(rows)} checked services"
        except OSError:
            result.summary = "completed, but CSV output could not be parsed"

    return result
