"""Wrapper for SpiderFoot in CLI/scan mode (broad automated OSINT footprinting)."""

from __future__ import annotations

import json
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "spiderfoot"


def run(target: str, out_dir: Path, use_case: str = "passive", extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("spiderfoot")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "-s", target, "-u", use_case, "-o", "json", "-q"]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    out_path = tool_dir / "spiderfoot.json"
    if result.stdout_path and result.stdout_path.exists():
        content = result.stdout_path.read_text()
        out_path.write_text(content)
        result.output_files.append(out_path)
        try:
            events = json.loads(content)
            result.summary = f"{len(events)} event(s) collected"
        except json.JSONDecodeError:
            result.summary = "completed, but output was not valid JSON (see stdout.log)"

    return result
