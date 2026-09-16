"""Wrapper for sherlock (username -> social media presence)."""

from __future__ import annotations

import csv
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "sherlock"


def run(username: str, out_dir: Path, sites: list[str] | None = None, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("sherlock")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, username, "--csv", "--folderoutput", str(tool_dir), "--timeout", "30"]
    for site in sites or []:
        cmd += ["--site", site]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    csv_path = tool_dir / f"{username}.csv"
    if csv_path.exists():
        result.output_files.append(csv_path)
        try:
            with csv_path.open(newline="") as fh:
                rows = list(csv.DictReader(fh))
            # Sherlock's CSV only contains claimed rows by default (--print-found).
            found = sum(1 for r in rows if "claimed" in str(r.get("exists", "")).lower())
            result.summary = f"{found} site(s) matched" if found else "no matches"
        except OSError:
            result.summary = "completed, but CSV output could not be parsed"

    return result
