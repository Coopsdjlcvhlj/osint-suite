"""Shared helpers for shelling out to wrapped OSINT tools and organizing results."""

from __future__ import annotations

import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

RESULTS_ROOT = Path.cwd() / "osint-results"

# Maps a CLI binary name to the pacman package that provides it, so a missing
# tool produces an actionable error instead of a bare "command not found".
PACMAN_PACKAGE = {
    "theHarvester": "theharvester-git",
    "sherlock": "sherlock-git",
    "amass": "amass",
    "holehe": "holehe",
    "spiderfoot": "spiderfoot",
    "shodan": "shodan",
    "recon-ng": "recon-ng",
    "whois": "whois",
    "dnsrecon": "python-dnsrecon",
}


class ToolUnavailable(RuntimeError):
    pass


@dataclass
class ToolResult:
    tool: str
    command: list[str]
    returncode: int
    duration_seconds: float
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    output_files: list[Path] = field(default_factory=list)
    summary: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "command": self.command,
            "returncode": self.returncode,
            "ok": self.ok,
            "duration_seconds": round(self.duration_seconds, 2),
            "stdout_path": str(self.stdout_path) if self.stdout_path else None,
            "stderr_path": str(self.stderr_path) if self.stderr_path else None,
            "output_files": [str(p) for p in self.output_files],
            "summary": self.summary,
        }


def sanitize(target: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._@-]+", "_", target.strip())
    return cleaned.strip("_") or "target"


def new_run_dir(target: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_dir = RESULTS_ROOT / sanitize(target) / stamp
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def require_binary(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        pkg = PACMAN_PACKAGE.get(name, name)
        raise ToolUnavailable(
            f"'{name}' is not installed or not on PATH. Install it with: sudo pacman -S {pkg}"
            if pkg != name
            else f"'{name}' is not installed or not on PATH."
        )
    return path


def run_cmd(
    tool: str,
    cmd: list[str],
    out_dir: Path,
    cwd: Path | None = None,
    timeout: int | None = None,
) -> ToolResult:
    """Run cmd, tee stdout/stderr to files under out_dir, and return a ToolResult."""
    tool_dir = out_dir / tool
    tool_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = tool_dir / "stdout.log"
    stderr_path = tool_dir / "stderr.log"

    start = time.monotonic()
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd or tool_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        returncode = proc.returncode
        stdout_path.write_text(proc.stdout)
        stderr_path.write_text(proc.stderr)
    except subprocess.TimeoutExpired as exc:
        returncode = -1
        stdout_path.write_text(exc.stdout or "")
        stderr_path.write_text((exc.stderr or "") + f"\n[osint-suite] timed out after {timeout}s\n")
    duration = time.monotonic() - start

    return ToolResult(
        tool=tool,
        command=cmd,
        returncode=returncode,
        duration_seconds=duration,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
    )
