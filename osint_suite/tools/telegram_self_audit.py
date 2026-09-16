"""Audit how exposed YOUR OWN Telegram account is, using the official MTProto
API on your own logged-in session.

This deliberately does not try to resolve or import anyone else's phone
number. It reads the privacy rules and active sessions attached to your own
account, i.e. it answers "what would a stranger see about me", not "what can
I find out about someone else". That is the same information a contact-import
bot exploits (see the phone-number and added-by-phone privacy keys) — this
tool just shows it to the account owner instead.

Requires:
  - `pip install telethon` (already added to the project venv)
  - your own api_id / api_hash from https://my.telegram.org/apps
  - an interactive terminal the first time, to enter the login code Telegram
    sends you (a session file is cached afterwards so later runs are silent)
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path

DEFAULT_SESSION_DIR = Path.home() / ".config" / "osint-suite"
DEFAULT_SESSION_FILE = DEFAULT_SESSION_DIR / "telegram_self_audit.session"


@dataclass
class PrivacyFinding:
    key: str
    verdict: str
    detail: str
    risky: bool


def _describe_rules(rules) -> tuple[str, str]:
    """Collapse Telegram's ordered allow/disallow rule list into a plain-English verdict."""
    from telethon.tl.types import (
        PrivacyValueAllowAll,
        PrivacyValueAllowChatParticipants,
        PrivacyValueAllowCloseFriends,
        PrivacyValueAllowContacts,
        PrivacyValueAllowUsers,
        PrivacyValueDisallowAll,
        PrivacyValueDisallowChatParticipants,
        PrivacyValueDisallowContacts,
        PrivacyValueDisallowUsers,
    )

    kinds = [type(r).__name__ for r in rules]
    exceptions = []
    for r in rules:
        if isinstance(r, (PrivacyValueAllowUsers, PrivacyValueDisallowUsers)):
            exceptions.append(f"{len(r.users)} user exception(s)")
        if isinstance(r, (PrivacyValueAllowChatParticipants, PrivacyValueDisallowChatParticipants)):
            exceptions.append(f"{len(r.chats)} chat exception(s)")

    detail = f"raw rules: {kinds}" + (f" ({', '.join(exceptions)})" if exceptions else "")

    if not rules:
        return "Everybody (default, no rule set)", detail
    if any(isinstance(r, PrivacyValueAllowAll) for r in rules):
        return "Everybody", detail
    if any(isinstance(r, PrivacyValueDisallowAll) for r in rules):
        return "Nobody", detail
    if any(isinstance(r, PrivacyValueAllowContacts) for r in rules):
        return "My Contacts", detail
    if any(isinstance(r, PrivacyValueAllowCloseFriends) for r in rules):
        return "Close Friends only", detail
    if any(isinstance(r, PrivacyValueDisallowContacts) for r in rules):
        return "Everybody except contacts", detail
    return "Custom", detail


async def _audit(api_id: int, api_hash: str, session_path: Path) -> dict:
    from telethon import TelegramClient
    from telethon.tl.functions.account import GetAuthorizationsRequest, GetPrivacyRequest
    from telethon.tl.types import (
        InputPrivacyKeyAddedByPhone,
        InputPrivacyKeyPhoneNumber,
        InputPrivacyKeyProfilePhoto,
        InputPrivacyKeyStatusTimestamp,
    )

    session_path.parent.mkdir(parents=True, exist_ok=True)
    client = TelegramClient(str(session_path), api_id, api_hash)
    await client.start()  # interactive on first run (phone + code); cached after

    me = await client.get_me()

    findings: list[PrivacyFinding] = []

    phone_rules = (await client(GetPrivacyRequest(InputPrivacyKeyPhoneNumber()))).rules
    verdict, detail = _describe_rules(phone_rules)
    findings.append(PrivacyFinding(
        key="Who can see my phone number",
        verdict=verdict,
        detail=detail,
        risky=verdict in ("Everybody", "Custom"),
    ))

    findby_rules = (await client(GetPrivacyRequest(InputPrivacyKeyAddedByPhone()))).rules
    verdict, detail = _describe_rules(findby_rules)
    findings.append(PrivacyFinding(
        key="Who can find me by phone number (the contact-import vector)",
        verdict=verdict,
        detail=detail,
        risky=verdict != "Nobody",
    ))

    photo_rules = (await client(GetPrivacyRequest(InputPrivacyKeyProfilePhoto()))).rules
    verdict, detail = _describe_rules(photo_rules)
    findings.append(PrivacyFinding(
        key="Who can see my profile photo",
        verdict=verdict,
        detail=detail,
        risky=verdict == "Everybody",
    ))

    status_rules = (await client(GetPrivacyRequest(InputPrivacyKeyStatusTimestamp()))).rules
    verdict, detail = _describe_rules(status_rules)
    findings.append(PrivacyFinding(
        key="Who can see my last-seen time",
        verdict=verdict,
        detail=detail,
        risky=verdict == "Everybody",
    ))

    auths = (await client(GetAuthorizationsRequest())).authorizations
    sessions = [
        {
            "app": a.app_name,
            "platform": a.platform,
            "device": a.device_model,
            "ip": a.ip,
            "country": a.country,
            "current": a.current,
            "date_active": str(a.date_active),
        }
        for a in auths
    ]

    await client.disconnect()

    return {
        "account": {
            "id": me.id,
            "username": me.username,
            "first_name": me.first_name,
            "phone_last4": (me.phone[-4:] if getattr(me, "phone", None) else None),
        },
        "findings": [f.__dict__ for f in findings],
        "active_sessions": sessions,
    }


def run(api_id: int, api_hash: str, out_dir: Path, session_path: Path | None = None) -> dict:
    """Runs interactively in the current terminal (login prompts on first use)."""
    session_path = session_path or DEFAULT_SESSION_FILE
    result = asyncio.run(_audit(api_id, api_hash, session_path))

    tool_dir = out_dir / "telegram_self_audit"
    tool_dir.mkdir(parents=True, exist_ok=True)

    import json
    (tool_dir / "report.json").write_text(json.dumps(result, indent=2, default=str))

    lines = [f"# Telegram self-exposure audit", ""]
    acct = result["account"]
    lines.append(f"Account: {acct.get('first_name')} (@{acct.get('username')}), id={acct['id']}")
    lines.append("")
    for f in result["findings"]:
        flag = "⚠" if f["risky"] else "✓"
        lines.append(f"{flag} **{f['key']}**: {f['verdict']}")
        lines.append(f"    {f['detail']}")
    lines.append("")
    lines.append(f"## Active sessions ({len(result['active_sessions'])})")
    for s in result["active_sessions"]:
        marker = " (this session)" if s["current"] else ""
        lines.append(f"- {s['app']} on {s['platform']}/{s['device']} — IP {s['ip']} ({s['country']}), last active {s['date_active']}{marker}")
    (tool_dir / "report.md").write_text("\n".join(lines))

    return result
