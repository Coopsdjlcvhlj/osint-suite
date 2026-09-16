"""Wrapper for PhoneInfoga (footprint scan: carrier dorks, disposable-number and
reputation lookups via free scanners). Text-only CLI output — no JSON flag in v2.
"""

from __future__ import annotations

import re
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "phoneinfoga"

_SCANNER_RE = re.compile(r"^Results for (\S+)", re.MULTILINE)
_URL_RE = re.compile(r"^\s*URL:", re.MULTILINE)


def run(number: str, out_dir: Path, disable: list[str] | None = None, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("phoneinfoga-bin")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "scan", "-n", number]
    for scanner in disable or []:
        cmd += ["-D", scanner]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if result.stdout_path and result.stdout_path.exists():
        text = result.stdout_path.read_text()
        scanners = _SCANNER_RE.findall(text)
        urls = len(_URL_RE.findall(text))
        result.summary = f"{len(scanners)} scanner(s) with hits, {urls} lead(s): {', '.join(scanners) or 'none'}"

    return result
