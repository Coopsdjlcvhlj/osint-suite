"""Wrapper for OWASP Amass (subdomain enumeration / attack surface mapping)."""

from __future__ import annotations

from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "amass"


def run(domain: str, out_dir: Path, active: bool = False, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("amass")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)
    out_basename = tool_dir / "amass"

    cmd = [binary, "enum", "-d", domain, "-dir", str(tool_dir), "-oA", str(out_basename)]
    cmd += ["-active"] if active else []
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    # amass v5 no longer prints discovered names to stdout (only a progress
    # bar) — the actual names land in the -oA output files instead.
    txt_path = out_basename.with_suffix(".txt")
    if txt_path.exists():
        result.output_files.append(txt_path)
        names = [l for l in txt_path.read_text().splitlines() if l.strip()]
        result.summary = f"{len(names)} name(s) discovered"
    else:
        result.summary = "0 name(s) discovered"
    json_path = out_basename.with_suffix(".json")
    if json_path.exists():
        result.output_files.append(json_path)

    return result
