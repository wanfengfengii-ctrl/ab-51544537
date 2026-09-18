"""Shared helpers for the acceptance suite.

Tests run inside the `verify` container against the full stack (proxy, two API
replicas, two workers, database, mock actuator) — nothing is mocked.
"""
from __future__ import annotations

import base64
import os
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.canonical import command_canonical, signature_message

BASE_URL = os.environ.get("BASE_URL", "http://proxy").rstrip("/")
ACTUATOR_URL = os.environ.get("ACTUATOR_URL", "http://actuator:8090")
POLICY_VERSION = 1
SUBMITTER = "dispatcher-system"


def new_key(subject: str, role: str):
    priv = Ed25519PrivateKey.generate()
    pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return priv, pem


def register_key(subject: str, role: str):
    priv, pem = new_key(subject, role)
    resp = requests.post(f"{BASE_URL}/api/v1/keys", json={
        "subject": subject, "role": role, "publicKeyPem": pem,
    }, timeout=10)
    assert resp.status_code == 201, resp.text
    return priv, pem, resp.json()["keyId"]


def iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def make_command_body(**overrides) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    body = {
        "commandId": f"cmd-{uuid.uuid4().hex[:16]}",
        "submitter": SUBMITTER,
        "station": "ST-777",
        "device": "BREAKER-01",
        "action": "OPEN",
        "params": {"phaseCount": 3, "interlock": True, "labels": ["a", "b"]},
        "notBefore": iso(now - timedelta(seconds=5)),
        "expiresAt": iso(now + timedelta(minutes=30)),
        "payloadVersion": 1,
    }
    body.update(overrides)
    return body


def submit(body: dict | None = None, **overrides) -> dict:
    body = body or make_command_body(**overrides)
    resp = requests.post(f"{BASE_URL}/api/v1/commands", json=body, timeout=10)
    assert resp.status_code == 201, resp.text
    return resp.json()


def canonical_for(body: dict) -> bytes:
    return command_canonical(
        command_id=body["commandId"],
        station=body["station"],
        device=body["device"],
        action=body["action"],
        params=body["params"],
        not_before=datetime.fromisoformat(body["notBefore"].replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(body["expiresAt"].replace("Z", "+00:00")),
        payload_version=body["payloadVersion"],
    )


def sign(priv, pem, command_id: str, body: dict, role: str, subject: str) -> requests.Response:
    msg = signature_message(canonical_for(body), POLICY_VERSION, role)
    sig = base64.b64encode(priv.sign(msg)).decode()
    return requests.post(f"{BASE_URL}/api/v1/commands/{command_id}/sign", json={
        "role": role, "subject": subject, "publicKeyPem": pem,
        "signature": sig,
    }, timeout=10)


def get_command(command_id: str) -> dict:
    resp = requests.get(f"{BASE_URL}/api/v1/commands/{command_id}", timeout=10)
    assert resp.status_code == 200, resp.text
    return resp.json()


def wait_state(command_id: str, *states: str, timeout: float = 25.0) -> dict:
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        last = get_command(command_id)
        if last["state"] in states:
            return last
        time.sleep(0.2)
    raise AssertionError(f"{command_id} never reached {states}; last={last}")


def authorize(body: dict, op=("operator-alice", "OPERATOR"),
              sf=("safety-bob", "SAFETY")) -> tuple:
    """Register two distinct subjects and sign both roles. Returns key material
    as (op_priv, op_pem, sf_priv, sf_pem)."""
    op_subject, op_role = op
    sf_subject, sf_role = sf
    op_priv, op_pem, _ = register_key(op_subject, op_role)
    sf_priv, sf_pem, _ = register_key(sf_subject, sf_role)
    cid = body["commandId"]
    r1 = sign(op_priv, op_pem, cid, body, op_role, op_subject)
    assert r1.status_code == 200, r1.text
    r2 = sign(sf_priv, sf_pem, cid, body, sf_role, sf_subject)
    assert r2.status_code == 200, r2.text
    return op_priv, op_pem, sf_priv, sf_pem


def timeline(command_id: str, **params) -> dict:
    resp = requests.get(f"{BASE_URL}/api/v1/commands/{command_id}/timeline",
                        params=params, timeout=10)
    assert resp.status_code == 200, resp.text
    return resp.json()


def actuator_result(execution_key: str) -> dict:
    resp = requests.get(f"{ACTUATOR_URL}/result/{execution_key}", timeout=10)
    assert resp.status_code == 200, resp.text
    return resp.json()


@pytest.fixture
def op_key():
    return register_key("operator-alice", "OPERATOR")


@pytest.fixture
def sf_key():
    return register_key("safety-bob", "SAFETY")
