"""Thin passthrough wrapper for the Shodan CLI (requires `shodan init <API_KEY>` once)."""

from __future__ import annotations

from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "shodan"


def run(args: list[str], out_dir: Path) -> ToolResult:
    binary = require_binary("shodan")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, *args]
    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if result.stdout_path and result.stdout_path.exists():
        text = result.stdout_path.read_text()
        result.summary = f"{len(text.splitlines())} line(s) of output" if text.strip() else "no output"

    return result
