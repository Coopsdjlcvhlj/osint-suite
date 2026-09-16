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

# osint_suite/tools/phoneinfoga.py -> project root, where the shared .env lives
# (scanner API keys, e.g. NUMVERIFY_API_KEY, GOOGLE_API_KEY/GOOGLE_CSE_ID). The
# tool otherwise runs with cwd set to a fresh per-run results dir, so phoneinfoga's
# own default ".env in cwd" lookup would never find it without pointing at it explicitly.
_PROJECT_ENV_FILE = Path(__file__).resolve().parents[2] / ".env"


def run(number: str, out_dir: Path, disable: list[str] | None = None, extra_args: list[str] | None = None) -> ToolResult:
    binary = require_binary("phoneinfoga-bin")
    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)

    cmd = [binary, "scan", "-n", number]
    for scanner in disable or []:
        cmd += ["-D", scanner]
    if _PROJECT_ENV_FILE.exists():
        cmd += ["--env-file", str(_PROJECT_ENV_FILE)]
    cmd += extra_args or []

    result = run_cmd(TOOL, cmd, out_dir, cwd=tool_dir)

    if result.stdout_path and result.stdout_path.exists():
        text = result.stdout_path.read_text()
        scanners = _SCANNER_RE.findall(text)
        urls = len(_URL_RE.findall(text))
        result.summary = f"{len(scanners)} scanner(s) with hits, {urls} lead(s): {', '.join(scanners) or 'none'}"

    return result
