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
    "phoneinfoga-bin": "phoneinfoga-bin",
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

    @classmethod
    def unavailable(cls, tool: str, reason: str) -> ToolResult:
        """Record a requested tool that could not start, including in reports."""
        return cls(tool=tool, command=[], returncode=127, duration_seconds=0, summary=reason)

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
    return cleaned.strip("_.") or "target"


def new_run_dir(target: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    target_dir = RESULTS_ROOT / sanitize(target)
    target_dir.mkdir(parents=True, exist_ok=True)
    attempt = 0
    while True:
        run_dir = target_dir / (stamp if attempt == 0 else f"{stamp}-{attempt}")
        try:
            run_dir.mkdir()
        except FileExistsError:
            attempt += 1
        else:
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
    timeout: float | None = None,
) -> ToolResult:
    """Run cmd and save its output, including partial output on timeout."""
    tool_dir = out_dir / tool
    tool_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = tool_dir / "stdout.log"
    stderr_path = tool_dir / "stderr.log"

    start = time.monotonic()
    summary = ""
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd or tool_dir,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        returncode = proc.returncode
        stdout, stderr = proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as exc:
        returncode = -1
        # TimeoutExpired carries bytes even when subprocess.run uses text=True.
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        summary = f"timed out after {timeout}s"
        stderr += f"\n[osint-suite] {summary}\n"
    except OSError as exc:
        returncode = 127 if isinstance(exc, FileNotFoundError) else 126
        summary = f"could not start process: {exc}"
        stdout = ""
        stderr = f"[osint-suite] {summary}\n"
    duration = time.monotonic() - start
    stdout_path.write_text(stdout, encoding="utf-8")
    stderr_path.write_text(stderr, encoding="utf-8")

    return ToolResult(
        tool=tool,
        command=cmd,
        returncode=returncode,
        duration_seconds=duration,
        stdout_path=stdout_path,
        stderr_path=stderr_path,
        summary=summary,
    )
