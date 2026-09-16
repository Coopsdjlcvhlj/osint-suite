"""Offline phone-number recon via the phonenumbers library (validity, region, carrier, line type).

Unlike the other wrappers this doesn't shell out to a binary — phonenumbers is
a Python library (the same data libphonenumber uses), so this calls it
in-process and writes the result out in the same report shape as every other
tool.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from osint_suite.runner import ToolResult, ToolUnavailable

TOOL = "phonenumbers"

_LINE_TYPES = {
    0: "FIXED_LINE",
    1: "MOBILE",
    2: "FIXED_LINE_OR_MOBILE",
    3: "TOLL_FREE",
    4: "PREMIUM_RATE",
    5: "SHARED_COST",
    6: "VOIP",
    7: "PERSONAL_NUMBER",
    8: "PAGER",
    9: "UAN",
    10: "VOICEMAIL",
    99: "UNKNOWN",
}


def run(number: str, out_dir: Path, region: str | None = None) -> ToolResult:
    try:
        import phonenumbers
        from phonenumbers import carrier, geocoder, timezone as tz_module
    except ImportError as exc:
        raise ToolUnavailable(
            "python 'phonenumbers' library is not installed. Install it with: sudo pacman -S python-phonenumbers"
        ) from exc

    tool_dir = out_dir / TOOL
    tool_dir.mkdir(parents=True, exist_ok=True)
    stdout_path = tool_dir / "stdout.log"
    json_path = tool_dir / "phonenumbers.json"

    start = time.monotonic()
    try:
        parsed = phonenumbers.parse(number, region)
        line_type = _LINE_TYPES.get(phonenumbers.number_type(parsed), "UNKNOWN")
        data = {
            "input": number,
            "e164": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "international": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "country_code": parsed.country_code,
            "region": geocoder.description_for_number(parsed, "en") or None,
            "carrier": carrier.name_for_number(parsed, "en") or None,
            "line_type": line_type,
            "timezones": list(tz_module.time_zones_for_number(parsed)),
        }
        returncode = 0
    except phonenumbers.NumberParseException as exc:
        data = {"input": number, "error": str(exc)}
        returncode = 1
    duration = time.monotonic() - start

    json_path.write_text(json.dumps(data, indent=2))
    stdout_path.write_text(json.dumps(data, indent=2))

    result = ToolResult(
        tool=TOOL,
        command=["python:phonenumbers.parse", number],
        returncode=returncode,
        duration_seconds=duration,
        stdout_path=stdout_path,
        output_files=[json_path],
    )
    if returncode == 0:
        bits = [data["e164"], f"valid={data['valid']}", data["line_type"]]
        if data["region"]:
            bits.append(data["region"])
        if data["carrier"]:
            bits.append(data["carrier"])
        result.summary = ", ".join(bits)
    else:
        result.summary = f"parse error: {data['error']}"

    return result
