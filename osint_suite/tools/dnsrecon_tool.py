"""Wrapper for dnsrecon (DNS enumeration: SOA/NS/MX/TXT records, zone-transfer check)."""

from __future__ import annotations

import json
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "dnsrecon"


def run(domain: str, out_dir: Path, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("dnsrecon")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)
    json_path = tool_dir / "dnsrecon.json"

    cmd = [binary, "-d", domain, "-j", str(json_path)]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if json_path.exists():
        result.output_files.append(json_path)
        try:
            records = json.loads(json_path.read_text())
            result.summary = f"{len(records)} record(s) found"
        except (json.JSONDecodeError, OSError):
            result.summary = "completed, but JSON output could not be parsed"

    return result
