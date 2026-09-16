"""Wrapper for recon-ng batch mode via a resource file.

recon-ng is module-driven and normally interactive, so this only supports
non-interactive runs against a `.rc` resource file (a sequence of recon-ng
commands, e.g. `modules load recon/domains-hosts/hackertarget` /
`options set SOURCE example.com` / `run`). For exploratory use, run
`recon-ng -w <workspace>` directly in a terminal.
"""

from __future__ import annotations

from pathlib import Path

from osint_suite.runner import ToolResult, ToolUnavailable, require_binary, run_cmd

TOOL = "recon-ng"


def run(workspace: str, resource_file: str, out_dir: Path) -> ToolResult:
    binary = require_binary("recon-ng")
    resource_path = Path(resource_file).expanduser()
    if not resource_path.is_file():
        raise ToolUnavailable(f"recon-ng resource file not found: {resource_path}")

    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "-w", workspace, "-r", str(resource_path), "--no-analytics", "--no-version"]
    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if result.stdout_path and result.stdout_path.exists():
        result.summary = "see stdout.log for module output (results also live in the recon-ng workspace db)"

    return result
