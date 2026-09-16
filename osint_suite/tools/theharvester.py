"""Wrapper for theHarvester (domain/company recon: subdomains, emails, IPs)."""

from __future__ import annotations

import json
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "theharvester"


def run(domain: str, out_dir: Path, sources: str = "all", limit: int = 500, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("theHarvester")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)
    out_basename = tool_dir / "theharvester"

    cmd = [binary, "-d", domain, "-b", sources, "-l", str(limit), "-f", str(out_basename)]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    json_path = out_basename.with_suffix(".json")
    if json_path.exists():
        result.output_files.append(json_path)
        try:
            data = json.loads(json_path.read_text())
            hosts = len(data.get("hosts", []) or [])
            emails = len(data.get("emails", []) or [])
            ips = len(data.get("ips", []) or [])
            result.summary = f"{hosts} hosts, {emails} emails, {ips} ips"
        except (json.JSONDecodeError, OSError):
            result.summary = "completed, but JSON output could not be parsed"
    for suffix in (".xml", ".jsonl"):
        p = out_basename.with_suffix(suffix)
        if p.exists():
            result.output_files.append(p)

    return result
