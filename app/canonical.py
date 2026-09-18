"""Deterministic byte encoding for command payloads and signature messages.

Format (all multi-byte integers are ASCII decimal byte lengths; raw UTF-8
bytes follow, so embedded newlines or ':' in values can never create
ambiguity):

    SUBSTATION-CMD-v1\n
    commandId:<len>:<utf8 bytes>\n
    station:<len>:<bytes>\n
    device:<len>:<bytes>\n
    action:<len>:<bytes>\n
    params:<len>:<canonical JSON bytes>\n
    notBefore:<len>:<RFC3339 UTC, microsecond precision, trailing Z>\n
    expiresAt:<len>:<...>\n
    payloadVersion:<len>:<ASCII decimal>\n

The signature message for role R under policy P is exactly:

    SUBSTATION-CMD-SIG-v1\n
    <the command bytes above>
    policyVersion:<len>:<ASCII decimal>\n
    role:<len>:<OPERATOR|SAFETY>\n

Clients MUST construct the message from this specification rather than
re-serialize a JSON object: object key order must never influence the bytes.

Canonical JSON for `params`: UTF-8, no insignificant whitespace, object
members sorted by Unicode code point (json.dumps(sort_keys)), booleans/null
as JSON literals. Integers and floats keep their parsed kind (1 vs 1.0).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

CMD_MAGIC = b"SUBSTATION-CMD-v1\n"
SIG_MAGIC = b"SUBSTATION-CMD-SIG-v1\n"

_CMD_ORDER = ("commandId", "station", "device", "action", "params",
              "notBefore", "expiresAt", "payloadVersion")


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def format_ts(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


def _segment(name: str, raw: bytes) -> bytes:
    return f"{name}:{len(raw)}:".encode("ascii") + raw + b"\n"


def command_canonical(*, command_id: str, station: str, device: str,
                      action: str, params: Any, not_before: datetime,
                      expires_at: datetime, payload_version: int) -> bytes:
    values = {
        "commandId": command_id.encode("utf-8"),
        "station": station.encode("utf-8"),
        "device": device.encode("utf-8"),
        "action": action.encode("utf-8"),
        "params": canonical_json(params),
        "notBefore": format_ts(not_before).encode("ascii"),
        "expiresAt": format_ts(expires_at).encode("ascii"),
        "payloadVersion": str(payload_version).encode("ascii"),
    }
    out = [CMD_MAGIC]
    for key in _CMD_ORDER:
        out.append(_segment(key, values[key]))
    return b"".join(out)


def signature_message(command_bytes: bytes, policy_version: int,
                      role: str) -> bytes:
    if role not in ("OPERATOR", "SAFETY"):
        raise ValueError("role must be OPERATOR or SAFETY")
    out = [SIG_MAGIC, command_bytes]
    out.append(_segment("policyVersion", str(policy_version).encode("ascii")))
    out.append(_segment("role", role.encode("ascii")))
    return b"".join(out)
