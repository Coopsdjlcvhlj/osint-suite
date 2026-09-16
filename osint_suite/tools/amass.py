"""Wrapper for OWASP Amass (subdomain enumeration / attack surface mapping)."""

from __future__ import annotations

from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "amass"


def run(domain: str, out_dir: Path, active: bool = False, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("amass")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "enum", "-d", domain, "-dir", str(tool_dir)]
    cmd += ["-active"] if active else ["-passive"]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if result.stdout_path and result.stdout_path.exists():
        lines = [l for l in result.stdout_path.read_text().splitlines() if l.strip()]
        result.summary = f"{len(lines)} name(s) discovered"
    for candidate in tool_dir.rglob("*"):
        if candidate.is_file() and candidate.name not in {"stdout.log", "stderr.log"}:
            result.output_files.append(candidate)

    return result
