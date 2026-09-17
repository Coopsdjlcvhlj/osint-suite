"""osint-suite: a single CLI that orchestrates the OSINT tools installed on this
machine (theHarvester, sherlock, amass, holehe, spiderfoot, shodan, recon-ng)
and collects their output under one results tree.

Usage:
    python3 -m osint_suite list-tools
    python3 -m osint_suite domain example.com
    python3 -m osint_suite username johndoe
    python3 -m osint_suite email john@example.com
    python3 -m osint_suite phone +14155552671 --deep
    python3 -m osint_suite pivot example.com --type domain --depth 1
    python3 -m osint_suite spiderfoot example.com --use-case footprint
    python3 -m osint_suite shodan host 1.1.1.1
    python3 -m osint_suite recon myworkspace --resource-file recon.rc
    python3 -m osint_suite all example.com --type domain
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from osint_suite import pivot
from osint_suite.report import write_report
from osint_suite.runner import PACMAN_PACKAGE, ToolResult, ToolUnavailable, new_run_dir
from osint_suite.tools import (
    amass,
    dnsrecon_tool,
    holehe,
    phone_lookup,
    phoneinfoga,
    recon_ng,
    sherlock,
    shodan_tool,
    spiderfoot,
    theharvester,
    whois_tool,
)


def _print_result(r: ToolResult) -> None:
    status = "ok" if r.ok else f"FAILED (exit {r.returncode})"
    line = f"[{r.tool}] {status}"
    if r.summary:
        line += f" — {r.summary}"
    print(line)
    if not r.ok and r.stderr_path and r.stderr_path.exists():
        tail = r.stderr_path.read_text().strip().splitlines()[-5:]
        for l in tail:
            print(f"    {l}")


def _finish(target: str, run_dir: Path, results: list[ToolResult]) -> None:
    json_path, md_path = write_report(target, run_dir, results)
    print()
    print(f"Report: {md_path}")
    print(f"Manifest: {json_path}")


def cmd_list_tools(_args: argparse.Namespace) -> int:
    print(f"{'tool':<15} {'status':<12} path/hint")
    for name, pkg in PACMAN_PACKAGE.items():
        path = shutil.which(name)
        if path:
            print(f"{name:<15} {'available':<12} {path}")
        else:
            print(f"{name:<15} {'missing':<12} sudo pacman -S {pkg}")
    return 0


def cmd_domain(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    results = []
    tools = args.tools or ["theharvester", "amass"]
    for name in tools:
        try:
            if name == "theharvester":
                results.append(theharvester.run(args.target, run_dir, limit=args.limit))
            elif name == "amass":
                results.append(amass.run(args.target, run_dir, active=args.active))
            elif name == "shodan":
                results.append(shodan_tool.run(["domain", args.target], run_dir))
            elif name == "spiderfoot":
                results.append(spiderfoot.run(args.target, run_dir))
            elif name == "whois":
                results.append(whois_tool.run(args.target, run_dir))
            elif name == "dnsrecon":
                results.append(dnsrecon_tool.run(args.target, run_dir))
            else:
                print(f"[skip] unknown tool for domain scan: {name}")
                continue
        except ToolUnavailable as exc:
            results.append(ToolResult.unavailable(name, str(exc)))
            _print_result(results[-1])
            continue
        _print_result(results[-1])
    _finish(args.target, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_username(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    results = []
    try:
        results.append(sherlock.run(args.target, run_dir, sites=args.site))
        _print_result(results[-1])
    except ToolUnavailable as exc:
        results.append(ToolResult.unavailable("sherlock", str(exc)))
        _print_result(results[-1])
    _finish(args.target, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_email(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    results = []
    try:
        results.append(holehe.run(args.target, run_dir, only_used=not args.all_sites))
        _print_result(results[-1])
    except ToolUnavailable as exc:
        results.append(ToolResult.unavailable("holehe", str(exc)))
        _print_result(results[-1])
    _finish(args.target, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_phone(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    results = []
    try:
        results.append(phone_lookup.run(args.target, run_dir, region=args.region))
        _print_result(results[-1])
    except ToolUnavailable as exc:
        results.append(ToolResult.unavailable("phonenumbers", str(exc)))
        _print_result(results[-1])
    if args.deep:
        try:
            results.append(phoneinfoga.run(args.target, run_dir, disable=args.disable))
            _print_result(results[-1])
        except ToolUnavailable as exc:
            results.append(ToolResult.unavailable("phoneinfoga", str(exc)))
            _print_result(results[-1])
    _finish(args.target, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_spiderfoot(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    results = []
    try:
        results.append(spiderfoot.run(args.target, run_dir, use_case=args.use_case))
        _print_result(results[-1])
    except ToolUnavailable as exc:
        results.append(ToolResult.unavailable("spiderfoot", str(exc)))
        _print_result(results[-1])
    _finish(args.target, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_shodan(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.args[0] if args.args else "shodan")
    results = []
    try:
        results.append(shodan_tool.run(args.args, run_dir))
        _print_result(results[-1])
        if results[-1].stdout_path:
            print(results[-1].stdout_path.read_text())
    except ToolUnavailable as exc:
        results.append(ToolResult.unavailable("shodan", str(exc)))
        _print_result(results[-1])
    _finish(args.args[0] if args.args else "shodan", run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_telegram_self_audit(args: argparse.Namespace) -> int:
    try:
        from osint_suite.tools import telegram_self_audit
    except ImportError:
        print("telethon is not installed. Install it with: pip install telethon")
        return 1

    run_dir = new_run_dir(f"telegram-self-{args.api_id}")
    session_path = Path(args.session).expanduser() if args.session else None
    print("If this is the first run, Telegram will text you a login code now — enter it when prompted.")
    result = telegram_self_audit.run(args.api_id, args.api_hash, run_dir, session_path=session_path)

    for f in result["findings"]:
        flag = "!!" if f["risky"] else "ok"
        print(f"[{flag}] {f['key']}: {f['verdict']}")
    print(f"\nActive sessions: {len(result['active_sessions'])}")
    for s in result["active_sessions"]:
        marker = " <- this one" if s["current"] else ""
        print(f"  - {s['app']} / {s['platform']} / {s['device']} — {s['ip']} ({s['country']}){marker}")

    tool_dir = run_dir / "telegram_self_audit"
    print(f"\nReport: {tool_dir / 'report.md'}")
    return 0


def cmd_pivot(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    print(f"Pivoting from {args.type}:{args.target} (depth<={args.depth}, max {args.max_events} events)")
    if args.type == "domain" and not args.allow_external:
        print("Scope: staying within the target domain's own subdomains. Use --allow-external to lift this.")
    results, graph = pivot.run_pivot(
        args.target,
        args.type,
        run_dir,
        max_depth=args.depth,
        max_events=args.max_events,
        module_names=args.modules,
        allow_external=args.allow_external,
    )
    graph_path = pivot.write_graph(run_dir, graph, args.target, args.type)
    _finish(args.target, run_dir, results)
    print(f"Pivot graph: {graph_path}")
    return 0 if results and all(r.ok for r in results) else 1


def cmd_recon(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.workspace)
    results = []
    try:
        results.append(recon_ng.run(args.workspace, args.resource_file, run_dir))
        _print_result(results[-1])
    except ToolUnavailable as exc:
        results.append(ToolResult.unavailable("recon-ng", str(exc)))
        _print_result(results[-1])
    _finish(args.workspace, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def cmd_all(args: argparse.Namespace) -> int:
    run_dir = new_run_dir(args.target)
    results = []

    plan = {
        "domain": [("theharvester", lambda: theharvester.run(args.target, run_dir, limit=args.limit)),
                   ("amass", lambda: amass.run(args.target, run_dir))],
        "email": [("holehe", lambda: holehe.run(args.target, run_dir))],
        "username": [("sherlock", lambda: sherlock.run(args.target, run_dir))],
    }[args.type]

    if args.spiderfoot:
        plan.append(("spiderfoot", lambda: spiderfoot.run(args.target, run_dir)))

    for name, action in plan:
        try:
            results.append(action())
            _print_result(results[-1])
        except ToolUnavailable as exc:
            results.append(ToolResult.unavailable(name, str(exc)))
            _print_result(results[-1])

    _finish(args.target, run_dir, results)
    return 0 if results and all(r.ok for r in results) else 1


def _nonnegative_int(value: str) -> int:
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return number


def _positive_int(value: str) -> int:
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be positive")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="osint", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list-tools", help="Show which OSINT tools are installed and on PATH")
    p.set_defaults(func=cmd_list_tools)

    p = sub.add_parser("domain", help="Run domain/company recon (theHarvester, amass, shodan, spiderfoot)")
    p.add_argument("target")
    p.add_argument("--tools", nargs="+", choices=["theharvester", "amass", "shodan", "spiderfoot", "whois", "dnsrecon"])
    p.add_argument("--limit", type=int, default=500, help="theHarvester result limit per source")
    p.add_argument("--active", action="store_true", help="Allow amass active techniques (default: passive only)")
    p.set_defaults(func=cmd_domain)

    p = sub.add_parser("username", help="Run username recon (sherlock)")
    p.add_argument("target")
    p.add_argument("--site", action="append", help="Limit sherlock to specific site(s); repeatable")
    p.set_defaults(func=cmd_username)

    p = sub.add_parser("phone", help="Run phone-number recon (phonenumbers, optionally phoneinfoga)")
    p.add_argument("target", help="Phone number in E164 or international format, e.g. +14155552671")
    p.add_argument("--region", help="Default region (e.g. US) to assume for a number with no country code")
    p.add_argument("--deep", action="store_true", help="Also run phoneinfoga (free-scanner footprint dorks)")
    p.add_argument("--disable", nargs="+", help="phoneinfoga scanner(s) to skip; only used with --deep")
    p.set_defaults(func=cmd_phone)

    p = sub.add_parser("email", help="Run email recon (holehe)")
    p.add_argument("target")
    p.add_argument("--all-sites", action="store_true", help="Include sites where the email is not registered")
    p.set_defaults(func=cmd_email)

    p = sub.add_parser("spiderfoot", help="Run a SpiderFoot scan against any target type")
    p.add_argument("target")
    p.add_argument("--use-case", default="passive", choices=["all", "footprint", "investigate", "passive"])
    p.set_defaults(func=cmd_spiderfoot)

    p = sub.add_parser("shodan", help="Passthrough to the shodan CLI, e.g. `osint shodan host 1.1.1.1`")
    p.add_argument("args", nargs=argparse.REMAINDER)
    p.set_defaults(func=cmd_shodan)

    p = sub.add_parser(
        "telegram-self-audit",
        help="Audit YOUR OWN Telegram account's exposure (phone-number privacy, active sessions)",
    )
    p.add_argument("--api-id", type=int, required=True, help="From https://my.telegram.org/apps")
    p.add_argument("--api-hash", required=True, help="From https://my.telegram.org/apps")
    p.add_argument("--session", help="Session file path (default: ~/.config/osint-suite/telegram_self_audit.session)")
    p.set_defaults(func=cmd_telegram_self_audit)

    p = sub.add_parser(
        "pivot",
        help="Event-driven recon: auto-chain discovered subdomains/emails/IPs/a validated phone number into follow-up tools",
    )
    p.add_argument("target")
    p.add_argument("--type", required=True, choices=["domain", "phone"])
    p.add_argument("--depth", type=_nonnegative_int, default=1, help="How many hops of pivoting to follow (default: 1)")
    p.add_argument("--max-events", type=_positive_int, default=15, help="Safety cap on total entities processed (default: 15)")
    p.add_argument("--modules", nargs="+", choices=pivot.module_names(), help="Restrict to specific pivot modules (default: all applicable)")
    p.add_argument("--allow-external", action="store_true", help="Allow pivoting to domains/subdomains outside the seed domain's scope")
    p.set_defaults(func=cmd_pivot)

    p = sub.add_parser("recon", help="Run recon-ng non-interactively against a resource (.rc) file")
    p.add_argument("workspace")
    p.add_argument("--resource-file", required=True)
    p.set_defaults(func=cmd_recon)

    p = sub.add_parser("all", help="Run the full applicable tool pipeline for a target type")
    p.add_argument("target")
    p.add_argument("--type", required=True, choices=["domain", "email", "username"])
    p.add_argument("--limit", type=int, default=500, help="theHarvester result limit per source (domain type only)")
    p.add_argument("--spiderfoot", action="store_true", help="Also run a passive SpiderFoot scan")
    p.set_defaults(func=cmd_all)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
