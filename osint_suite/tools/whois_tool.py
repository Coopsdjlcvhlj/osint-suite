"""Wrapper for the whois client (registrar, creation/expiry dates, name servers)."""

from __future__ import annotations

import re
from pathlib import Path

from osint_suite.runner import ToolResult, require_binary, run_cmd

TOOL = "whois"

_FIELDS = {
    "registrar": re.compile(r"^Registrar:\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "created": re.compile(r"^(?:Creation Date|created):\s*(.+)$", re.IGNORECASE | re.MULTILINE),
    "expires": re.compile(r"^(?:Registry Expiry Date|Expiration Date|expires):\s*(.+)$", re.IGNORECASE | re.MULTILINE),
}


def run(target: str, out_dir: Path, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("whois")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, target] + (extra_args or [])
    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if result.stdout_path and result.stdout_path.exists():
        text = result.stdout_path.read_text()
        found = {}
        for name, pattern in _FIELDS.items():
            match = pattern.search(text)
            if match:
                found[name] = match.group(1).strip()
        if found:
            result.summary = ", ".join(f"{k}: {v}" for k, v in found.items())
        elif text.strip():
            result.summary = "raw whois output (no structured fields matched)"

    return result
