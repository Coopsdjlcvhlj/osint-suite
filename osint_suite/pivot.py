"""Event-driven pivot engine.

Chains the same tool wrappers used by the plain `domain`/`phone` commands:
running a module against a seed target can turn up new entities (a
subdomain, an email address, an IP, a validated phone number), and those get
queued as follow-up targets for whichever modules consume that entity type —
breadth-first, up to a depth and total-event budget. This doesn't reimplement
any tool logic, only the extraction of new pivot targets from each tool's own
output files, and the queue that drives it.
"""

from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from osint_suite.runner import ToolResult, ToolUnavailable, sanitize
from osint_suite.tools import amass, dnsrecon_tool, holehe, phone_lookup, phoneinfoga, spiderfoot, theharvester, whois_tool

DOMAIN = "domain"
SUBDOMAIN = "subdomain"
EMAIL = "email"
IP = "ip"
PHONE = "phone"
PHONE_VALID = "phone_valid"


@dataclass(frozen=True)
class Event:
    type: str
    value: str
    depth: int
    source_module: str | None = None
    parent: str | None = None


def _apex_scope(domain: str) -> str:
    return domain.lower().strip(".")


def _in_scope(host: str, apex: str) -> bool:
    host = host.lower().strip(".")
    return host == apex or host.endswith("." + apex)


def _json_output(result: ToolResult) -> dict | list | None:
    json_path = next((p for p in result.output_files if p.suffix == ".json"), None)
    if not json_path or not json_path.exists():
        return None
    try:
        return json.loads(json_path.read_text())
    except json.JSONDecodeError:
        return None


def _extract_theharvester(result: ToolResult, apex: str) -> list[tuple[str, str]]:
    data = _json_output(result)
    if not isinstance(data, dict):
        return []
    found: list[tuple[str, str]] = []
    for host in data.get("hosts") or []:
        name = host.split(":")[0].strip().strip("'\"")
        if name and name != apex:
            found.append((SUBDOMAIN, name))
    for email in data.get("emails") or []:
        addr = email.strip().strip("'\"")
        if addr:
            found.append((EMAIL, addr))
    for ip in data.get("ips") or []:
        addr = ip.strip()
        if addr:
            found.append((IP, addr))
    return found


def _extract_amass(result: ToolResult, apex: str) -> list[tuple[str, str]]:
    txt_path = next((p for p in result.output_files if p.suffix == ".txt"), None)
    if not txt_path or not txt_path.exists():
        return []
    found: list[tuple[str, str]] = []
    for line in txt_path.read_text().splitlines():
        name = line.strip()
        if name and name != apex:
            found.append((SUBDOMAIN, name))
    return found


def _extract_dnsrecon(result: ToolResult, apex: str) -> list[tuple[str, str]]:
    records = _json_output(result)
    if not isinstance(records, list):
        return []
    found: list[tuple[str, str]] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        for key in ("target", "name", "exchange", "mname"):
            name = rec.get(key)
            if name and name != apex:
                found.append((SUBDOMAIN, name))
        addr = rec.get("address")
        if addr:
            found.append((IP, addr))
    return found


_SPIDERFOOT_TYPE_MAP = {
    "Internet Name": SUBDOMAIN,
    "Email Address": EMAIL,
    "IP Address": IP,
}


def _extract_spiderfoot(result: ToolResult, apex: str) -> list[tuple[str, str]]:
    events = _json_output(result)
    if not isinstance(events, list):
        return []
    found: list[tuple[str, str]] = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        kind = _SPIDERFOOT_TYPE_MAP.get(ev.get("type"))
        if not kind:
            continue
        value = (ev.get("data") or "").strip()
        if not value or value == apex:
            continue
        found.append((kind, value))
    return found


def _extract_phonenumbers(result: ToolResult, _apex: str) -> list[tuple[str, str]]:
    data = _json_output(result)
    if isinstance(data, dict) and data.get("valid"):
        return [(PHONE_VALID, data["e164"])]
    return []


def _noop(_result: ToolResult, _apex: str) -> list[tuple[str, str]]:
    return []


@dataclass
class PivotModule:
    name: str
    consumes: set[str]
    runner: Callable[[str, Path], ToolResult]
    extract: Callable[[ToolResult, str], list[tuple[str, str]]]


def _modules() -> list[PivotModule]:
    return [
        PivotModule("theharvester", {DOMAIN}, lambda v, d: theharvester.run(v, d), _extract_theharvester),
        PivotModule("amass", {DOMAIN}, lambda v, d: amass.run(v, d), _extract_amass),
        PivotModule("dnsrecon", {DOMAIN, SUBDOMAIN}, lambda v, d: dnsrecon_tool.run(v, d), _extract_dnsrecon),
        PivotModule("whois", {DOMAIN}, lambda v, d: whois_tool.run(v, d), _noop),
        PivotModule("spiderfoot", {DOMAIN}, lambda v, d: spiderfoot.run(v, d, use_case="passive"), _extract_spiderfoot),
        PivotModule("holehe", {EMAIL}, lambda v, d: holehe.run(v, d), _noop),
        PivotModule("phonenumbers", {PHONE}, lambda v, d: phone_lookup.run(v, d), _extract_phonenumbers),
        PivotModule("phoneinfoga", {PHONE_VALID}, lambda v, d: phoneinfoga.run(v, d), _noop),
    ]


def module_names() -> list[str]:
    return [module.name for module in _modules()]


def run_pivot(
    target: str,
    target_type: str,
    run_dir: Path,
    max_depth: int = 1,
    max_events: int = 15,
    module_names: list[str] | None = None,
    allow_external: bool = False,
) -> tuple[list[ToolResult], list[dict]]:
    if max_depth < 0:
        raise ValueError("max_depth must be non-negative")
    if max_events < 1:
        raise ValueError("max_events must be positive")
    available = _modules()
    unknown = set(module_names or []) - {mod.name for mod in available}
    if unknown:
        raise ValueError(f"unknown pivot module(s): {', '.join(sorted(unknown))}")
    apex = _apex_scope(target) if target_type in (DOMAIN, SUBDOMAIN) else ""
    mods = [m for m in available if not module_names or m.name in module_names]

    seen: set[tuple[str, str]] = {(target_type, target.lower())}
    queue: deque[Event] = deque([Event(type=target_type, value=target, depth=0)])
    graph: list[dict] = []
    results: list[ToolResult] = []
    processed = 0

    while queue and processed < max_events:
        event = queue.popleft()
        processed += 1
        for mod in mods:
            if event.type not in mod.consumes:
                continue
            event_dir = run_dir / "pivot" / f"d{event.depth}-{sanitize(event.type)}-{sanitize(event.value)}"
            try:
                result = mod.runner(event.value, event_dir)
            except ToolUnavailable as exc:
                result = ToolResult.unavailable(mod.name, str(exc))
            results.append(result)
            status = "ok" if result.ok else f"FAILED ({result.returncode})"
            summary = f" — {result.summary}" if result.summary else ""
            print(f"[depth {event.depth}] {mod.name}({event.type}:{event.value}) — {status}{summary}")

            graph.append(
                {
                    "depth": event.depth,
                    "module": mod.name,
                    "input_type": event.type,
                    "input_value": event.value,
                    "ok": result.ok,
                    "source_module": event.source_module,
                    "parent": event.parent,
                }
            )

            if event.depth >= max_depth or not result.ok:
                continue
            for new_type, new_value in mod.extract(result, apex):
                key = (new_type, new_value.lower())
                if key in seen:
                    continue
                if new_type in (DOMAIN, SUBDOMAIN) and not allow_external and apex and not _in_scope(new_value, apex):
                    continue
                seen.add(key)
                queue.append(Event(type=new_type, value=new_value, depth=event.depth + 1, source_module=mod.name, parent=f"{event.type}:{event.value}"))

    if queue:
        print(f"\n[pivot] hit --max-events cap ({max_events}); {len(queue)} discovered entit(y/ies) left unprocessed.")

    return results, graph


def write_graph(run_dir: Path, graph: list[dict], target: str, target_type: str) -> Path:
    md_path = run_dir / "pivot-graph.md"
    lines = [f"# Pivot graph: {target_type}:{target}", ""]
    for entry in graph:
        indent = "  " * entry["depth"]
        status = "OK" if entry["ok"] else "FAILED"
        lines.append(f"{indent}- [{status}] {entry['module']}({entry['input_type']}:{entry['input_value']})")
        if entry.get("parent"):
            lines.append(f"{indent}  - Discovered by {entry['source_module']} from `{entry['parent']}`")
    md_path.write_text("\n".join(lines))
    (run_dir / "pivot-graph.json").write_text(json.dumps(graph, indent=2))
    return md_path
