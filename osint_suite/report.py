"""Aggregate ToolResult objects from a run into a JSON manifest and a Markdown summary."""

from __future__ import annotations

import json
from pathlib import Path

from osint_suite.runner import ToolResult


def write_report(target: str, run_dir: Path, results: list[ToolResult]) -> tuple[Path, Path]:
    manifest = {
        "target": target,
        "run_dir": str(run_dir),
        "tools": [r.to_dict() for r in results],
    }
    json_path = run_dir / "report.json"
    json_path.write_text(json.dumps(manifest, indent=2))

    lines = [f"# OSINT report: {target}", "", f"Run directory: `{run_dir}`", ""]
    for r in results:
        status = "OK" if r.ok else f"FAILED (exit {r.returncode})"
        lines.append(f"## {r.tool} — {status}")
        lines.append(f"- Command: `{' '.join(r.command)}`" if r.command else "- Command: not started")
        lines.append(f"- Duration: {r.duration_seconds:.1f}s")
        if r.summary:
            lines.append(f"- Summary: {r.summary}")
        if r.output_files:
            lines.append("- Output files:")
            for f in r.output_files:
                lines.append(f"  - `{f}`")
        lines.append("")
    md_path = run_dir / "report.md"
    md_path.write_text("\n".join(lines))

    return json_path, md_path
