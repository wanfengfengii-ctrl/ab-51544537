"""Unit tests for the documented deterministic byte format."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from app import canonical


def test_command_bytes_exact_layout():
    dt1 = datetime(2026, 9, 18, 10, 0, 0, tzinfo=timezone.utc)
    dt2 = datetime(2026, 9, 18, 10, 30, 0, 123456, tzinfo=timezone.utc)
    raw = canonical.command_canonical(
        command_id="c1", station="S", device="D", action="OPEN",
        params={"b": 1, "a": "x"}, not_before=dt1, expires_at=dt2,
        payload_version=1,
    )
    text = raw.decode("utf-8")
    # Assert the concrete segments individually for precise failure output.
    assert text.startswith("SUBSTATION-CMD-v1\n")
    assert "commandId:2:c1\n" in text
    assert 'params:15:{"a":"x","b":1}\n' in text
    assert "notBefore:27:2026-09-18T10:00:00.000000Z\n" in text
    assert "expiresAt:27:2026-09-18T10:30:00.123456Z\n" in text
    assert "payloadVersion:1:1\n" in text


def test_params_key_order_independence():
    dt = datetime(2026, 9, 18, tzinfo=timezone.utc)
    kw = dict(command_id="c", station="s", device="d", action="a",
              not_before=dt, expires_at=dt, payload_version=1)
    a = canonical.command_canonical(params={"z": 1, "a": [1, 2]}, **kw)
    b = canonical.command_canonical(params={"a": [1, 2], "z": 1}, **kw)
    assert a == b


def test_embedded_separators_cannot_ambiguate():
    dt = datetime(2026, 9, 18, tzinfo=timezone.utc)
    raw = canonical.command_canonical(
        command_id="x:99:tricky\nstation:0:", station="s", device="d",
        action="a", params={}, not_before=dt, expires_at=dt, payload_version=2,
    ).decode()
    # Length prefixes protect the real field boundaries; station is still s.
    assert "commandId:22:x:99:tricky\nstation:0:\n" in raw
    assert "station:1:s\n" in raw


def test_signature_message_covers_policy_and_role():
    dt = datetime(2026, 9, 18, tzinfo=timezone.utc)
    cmd = canonical.command_canonical(
        command_id="c", station="s", device="d", action="a", params={"k": 0},
        not_before=dt, expires_at=dt, payload_version=1)
    op = canonical.signature_message(cmd, 7, "OPERATOR")
    sf = canonical.signature_message(cmd, 7, "SAFETY")
    other_policy = canonical.signature_message(cmd, 8, "OPERATOR")
    assert op.startswith(b"SUBSTATION-CMD-SIG-v1\n")
    assert op.endswith(b"policyVersion:1:7\nrole:8:OPERATOR\n")
    assert op != sf
    assert op != other_policy
    with pytest.raises(ValueError):
        canonical.signature_message(cmd, 7, "ADMIN")


def test_naive_datetime_rejected():
    dt = datetime(2026, 9, 18)
    with pytest.raises(ValueError):
        canonical.command_canonical(
            command_id="c", station="s", device="d", action="a", params={},
            not_before=dt, expires_at=dt, payload_version=1)
