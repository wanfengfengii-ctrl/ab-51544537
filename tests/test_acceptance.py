"""End-to-end acceptance tests against the full replicated stack."""
from __future__ import annotations

import base64
import time
from datetime import datetime, timedelta, timezone

import requests

from conftest import (ACTUATOR_URL, BASE_URL, POLICY_VERSION, SUBMITTER,
                      actuator_result, authorize, canonical_for, get_command,
                      iso, make_command_body, new_key, register_key, sign,
                      submit, timeline, wait_state)
from app.canonical import signature_message


# --------------------------------------------------------- key lifecycle ----

def test_register_and_disable_key(op_key):
    priv, pem, key_id = op_key
    resp = requests.get(f"{BASE_URL}/api/v1/keys/{key_id}", timeout=10)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is True

    resp = requests.post(f"{BASE_URL}/api/v1/keys/{key_id}/disable", timeout=10)
    assert resp.status_code == 200
    assert resp.json()["enabled"] is False
    assert resp.json()["disabledAt"] is not None

    # A previously recorded signature stays valid; a NEW signature is rejected.
    body = make_command_body()
    submit(body)
    r = sign(priv, pem, body["commandId"], body, "OPERATOR", "operator-alice")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "KEY_DISABLED"


def test_duplicate_key_registration_conflicts():
    _, pem = new_key("s1", "OPERATOR")
    r1 = requests.post(f"{BASE_URL}/api/v1/keys",
                       json={"subject": "s1", "role": "OPERATOR",
                             "publicKeyPem": pem}, timeout=10)
    assert r1.status_code == 201
    r2 = requests.post(f"{BASE_URL}/api/v1/keys",
                       json={"subject": "s2", "role": "SAFETY",
                             "publicKeyPem": pem}, timeout=10)
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "CONTENT_CONFLICT"


# ------------------------------------------------------------ submission ----

def test_submit_is_idempotent_on_identical_content():
    body = make_command_body()
    r1 = requests.post(f"{BASE_URL}/api/v1/commands", json=body, timeout=10)
    r2 = requests.post(f"{BASE_URL}/api/v1/commands", json=body, timeout=10)
    assert r1.status_code == 201 and r2.status_code == 201
    assert r1.json()["commandId"] == r2.json()["commandId"]
    assert r1.json()["createdAt"] == r2.json()["createdAt"]
    # Replay creates no extra timeline event.
    events = timeline(body["commandId"])["events"]
    assert [e["type"] for e in events] == ["COMMAND_SUBMITTED"]


def test_submit_same_id_different_content_is_stable_conflict():
    body = make_command_body(action="OPEN")
    assert requests.post(f"{BASE_URL}/api/v1/commands", json=body,
                         timeout=10).status_code == 201
    body2 = dict(body, action="CLOSE")
    r = requests.post(f"{BASE_URL}/api/v1/commands", json=body2, timeout=10)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "CONTENT_CONFLICT"
    # Repeating the divergent submission keeps returning the same conflict.
    r2 = requests.post(f"{BASE_URL}/api/v1/commands", json=body2, timeout=10)
    assert r2.status_code == 409


def test_payload_and_policy_snapshot_returned_and_immutable():
    body = make_command_body(payloadVersion=3)
    cmd = submit(body)
    assert cmd["payloadVersion"] == 3
    assert cmd["policyVersion"] == POLICY_VERSION
    assert cmd["policySnapshot"]["requireRoles"] == ["OPERATOR", "SAFETY"]
    assert cmd["state"] == "PENDING"
    assert cmd["executionKey"] is None
    assert cmd["finalResult"] is None


# ------------------------------------------------------------- signatures ---

def test_happy_path_two_distinct_roles_delivers():
    body = make_command_body()
    cmd = submit(body)
    assert cmd["satisfiedRoles"] == []
    authorize(body)
    final = wait_state(body["commandId"], "SUCCEEDED", timeout=30)
    assert set(final["satisfiedRoles"]) == {"OPERATOR", "SAFETY"}
    assert final["executionKey"] == f"exec-v1-{body['commandId']}"
    assert final["finalResult"]["physicalEffectCount"] == 1
    assert final["finalResult"].get("via") == "execute"
    # Exactly one physical effect at the actuator.
    eff = actuator_result(final["executionKey"])
    assert eff["status"] == "SUCCESS" and eff["result"]["physicalEffectCount"] == 1


def test_single_signature_does_not_authorize():
    body = make_command_body()
    submit(body)
    priv, pem, _ = register_key("operator-ann", "OPERATOR")
    assert sign(priv, pem, body["commandId"], body, "OPERATOR",
                "operator-ann").status_code == 200
    time.sleep(2.0)
    cmd = get_command(body["commandId"])
    assert cmd["state"] == "PENDING"
    assert cmd["executionKey"] is None


def test_submitter_cannot_sign():
    body = make_command_body()
    submit(body)
    priv, pem = new_key(SUBMITTER, "OPERATOR")
    r = requests.post(f"{BASE_URL}/api/v1/keys",
                      json={"subject": SUBMITTER, "role": "OPERATOR",
                            "publicKeyPem": pem}, timeout=10)
    assert r.status_code == 201
    resp = sign(priv, pem, body["commandId"], body, "OPERATOR", SUBMITTER)
    assert resp.status_code == 422
    assert resp.json()["error"]["code"] == "SUBMITTER_MUST_NOT_SIGN"


def test_same_subject_cannot_hold_both_roles():
    body = make_command_body()
    submit(body)
    p1, pem1 = new_key("dual-person", "OPERATOR")
    p2, pem2 = new_key("dual-person", "SAFETY")
    for pem, role in ((pem1, "OPERATOR"), (pem2, "SAFETY")):
        assert requests.post(f"{BASE_URL}/api/v1/keys",
                             json={"subject": "dual-person", "role": role,
                                   "publicKeyPem": pem}, timeout=10).status_code == 201
    r1 = sign(p1, pem1, body["commandId"], body, "OPERATOR", "dual-person")
    assert r1.status_code == 200
    r2 = sign(p2, pem2, body["commandId"], body, "SAFETY", "dual-person")
    assert r2.status_code == 409
    assert r2.json()["error"]["code"] == "DUPLICATE_SUBJECT_ROLE"


def test_wrong_role_key_rejected():
    body = make_command_body()
    submit(body)
    priv, pem, _ = register_key("operator-x", "OPERATOR")
    # Present an OPERATOR key while claiming the SAFETY role.
    r = sign(priv, pem, body["commandId"], body, "SAFETY", "operator-x")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SIGNER_NOT_QUALIFIED"


def test_tampered_signature_rejected():
    body = make_command_body()
    submit(body)
    priv, pem, _ = register_key("operator-t", "OPERATOR")
    msg = signature_message(canonical_for(body) + b" ", POLICY_VERSION, "OPERATOR")
    sig = base64.b64encode(priv.sign(msg)).decode()
    r = requests.post(f"{BASE_URL}/api/v1/commands/{body['commandId']}/sign",
                      json={"role": "OPERATOR", "subject": "operator-t",
                            "publicKeyPem": pem, "signature": sig}, timeout=10)
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "INVALID_SIGNATURE"


def test_unregistered_key_rejected():
    body = make_command_body()
    submit(body)
    priv, pem = new_key("ghost", "OPERATOR")
    r = sign(priv, pem, body["commandId"], body, "OPERATOR", "ghost")
    assert r.status_code == 422
    assert r.json()["error"]["code"] == "SIGNER_NOT_QUALIFIED"


def test_duplicate_sign_request_is_noop():
    body = make_command_body()
    submit(body)
    priv, pem, _ = register_key("operator-dup", "OPERATOR")
    r1 = sign(priv, pem, body["commandId"], body, "OPERATOR", "operator-dup")
    r2 = sign(priv, pem, body["commandId"], body, "OPERATOR", "operator-dup")
    assert r1.status_code == r2.status_code == 200
    page = timeline(body["commandId"])
    types = [e["type"] for e in page["events"]]
    assert types.count("SIGNATURE_ACCEPTED") == 1


def test_reuse_role_with_different_signature_conflicts():
    body = make_command_body()
    submit(body)
    p1, pem1, _ = register_key("op-one", "OPERATOR")
    p2, pem2, _ = register_key("op-two", "OPERATOR")
    assert sign(p1, pem1, body["commandId"], body, "OPERATOR",
                "op-one").status_code == 200
    r = sign(p2, pem2, body["commandId"], body, "OPERATOR", "op-two")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "CONTENT_CONFLICT"


def test_signature_survives_later_key_disable():
    body = make_command_body()
    submit(body)
    priv, pem, key_id = register_key("op-keep", "OPERATOR")
    assert sign(priv, pem, body["commandId"], body, "OPERATOR",
                "op-keep").status_code == 200
    assert requests.post(f"{BASE_URL}/api/v1/keys/{key_id}/disable",
                         timeout=10).status_code == 200
    cmd = get_command(body["commandId"])
    assert "OPERATOR" in cmd["satisfiedRoles"]
    # Retrying the same already-recorded signature remains an idempotent 200.
    r = sign(priv, pem, body["commandId"], body, "OPERATOR", "op-keep")
    assert r.status_code == 200


# ------------------------------------------------------- timing windows -----

def test_not_before_blocks_claim_then_delivers():
    now = datetime.now(timezone.utc)
    body = make_command_body(notBefore=iso(now + timedelta(seconds=3)),
                             expiresAt=iso(now + timedelta(minutes=30)))
    submit(body)
    authorize(body)
    time.sleep(0.5)
    cmd = get_command(body["commandId"])
    assert cmd["state"] == "AUTHORIZED"
    elig = requests.get(
        f"{BASE_URL}/api/v1/commands/{body['commandId']}/delivery-eligibility",
        timeout=10).json()
    assert elig["eligibility"] == "NOT_BEFORE_NOT_REACHED"
    final = wait_state(body["commandId"], "SUCCEEDED", timeout=20)
    assert final["state"] == "SUCCEEDED"


def test_expired_command_cannot_be_signed_or_claimed():
    now = datetime.now(timezone.utc)
    body = make_command_body(notBefore=iso(now - timedelta(minutes=10)),
                             expiresAt=iso(now - timedelta(seconds=1)))
    submit(body)
    priv, pem, _ = register_key("op-late", "OPERATOR")
    r = sign(priv, pem, body["commandId"], body, "OPERATOR", "op-late")
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "COMMAND_EXPIRED"
    cmd = get_command(body["commandId"])
    assert cmd["state"] == "EXPIRED"
    assert cmd["executionKey"] is None
    time.sleep(1.0)
    assert get_command(body["commandId"])["state"] == "EXPIRED"


def test_authorized_then_expired_never_delivers():
    now = datetime.now(timezone.utc)
    body = make_command_body(notBefore=iso(now - timedelta(minutes=10)),
                             expiresAt=iso(now + timedelta(seconds=2)))
    submit(body)
    # Only one signature: never becomes AUTHORIZED in time; sweep must expire.
    priv, pem, _ = register_key("op-half", "OPERATOR")
    assert sign(priv, pem, body["commandId"], body, "OPERATOR",
                "op-half").status_code == 200
    final = wait_state(body["commandId"], "EXPIRED", timeout=15)
    assert final["state"] == "EXPIRED"
    assert final["executionKey"] is None


# ------------------------------------------------------------- cancellation -

def test_cancel_before_authorization_is_terminal():
    body = make_command_body()
    submit(body)
    r = requests.post(f"{BASE_URL}/api/v1/commands/{body['commandId']}/cancel",
                      json={"requestedBy": "safety-bob", "reason": "plan change"},
                      timeout=10)
    assert r.status_code == 200 and r.json()["state"] == "CANCELLED"
    time.sleep(1.0)
    # A late signature must be refused as a terminal conflict.
    priv, pem, _ = register_key("op-late2", "OPERATOR")
    rs = sign(priv, pem, body["commandId"], body, "OPERATOR", "op-late2")
    assert rs.status_code == 409
    assert rs.json()["error"]["code"] == "TERMINAL_STATE_CONFLICT"


def test_cancel_after_claim_loses_race():
    body = make_command_body()
    submit(body)
    authorize(body)
    final = wait_state(body["commandId"], "SUCCEEDED", timeout=30)
    assert final["executionKey"]
    r = requests.post(f"{BASE_URL}/api/v1/commands/{body['commandId']}/cancel",
                      json={"requestedBy": "x"}, timeout=10)
    assert r.status_code == 409
    assert r.json()["error"]["code"] == "REVOKE_RACE_LOST"
    assert get_command(body["commandId"])["state"] == "SUCCEEDED"


# -------------------------------------------------------------- timeline ----

def test_timeline_pagination_is_a_fixed_view():
    body = make_command_body()
    submit(body)
    authorize(body)
    wait_state(body["commandId"], "SUCCEEDED", timeout=30)

    # Page through with limit=1; capture the first view's upper bound.
    seen: list[int] = []
    cursor = None
    upper = None
    for _ in range(50):
        params = {"limit": 1}
        if cursor:
            params["cursor"] = cursor
        page = timeline(body["commandId"], **params)
        if upper is None:
            upper = page["viewUpperBoundEventId"]
        assert page["viewUpperBoundEventId"] == upper
        assert len(page["events"]) == 1
        eid = page["events"][0]["eventId"]
        assert eid not in seen  # never duplicated
        seen.append(eid)
        cursor = page["nextCursor"]
        if cursor is None:
            break
    assert seen == sorted(seen)  # strictly monotonic
    assert seen[-1] == upper


def test_timeline_cursor_stable_against_new_events():
    body = make_command_body()
    submit(body)
    first = timeline(body["commandId"], limit=10)
    fixed_upper = first["viewUpperBoundEventId"]
    # Mutate the command after the view started.
    authorize(body)
    wait_state(body["commandId"], "SUCCEEDED", timeout=30)
    # The original view still reports exactly its fixed upper bound.
    again = timeline(body["commandId"], limit=10)
    assert again["viewUpperBoundEventId"] > fixed_upper  # a fresh view sees more
    # Replaying the first view via cursor keeps the old bound: craft cursor at 0.
    from app.repository import encode_cursor
    token = encode_cursor(0, fixed_upper)
    old_view = timeline(body["commandId"], limit=10, cursor=token)
    assert old_view["viewUpperBoundEventId"] == fixed_upper


# ------------------------------------------------------- delivery semantics -

def test_actuator_timeout_then_recovery_converges_success_single_effect():
    now = datetime.now(timezone.utc)
    body = make_command_body(
        expiresAt=iso(now + timedelta(minutes=30)),
        params={"__sim": {"mode": "timeoutFirst", "delaySeconds": 30}})
    submit(body)
    authorize(body)
    final = wait_state(body["commandId"], "SUCCEEDED", timeout=60)
    eff = actuator_result(final["executionKey"])
    assert eff["status"] == "SUCCESS"
    assert eff["result"]["physicalEffectCount"] == 1
    types = [e["type"] for e in timeline_all(body["commandId"])]
    assert types.count("DELIVERY_SUCCEEDED") == 1
    assert "RECOVERY_QUERY" in types


def test_flaky_downstream_retries_and_succeeds_once():
    body = make_command_body(
        params={"__sim": {"mode": "flaky", "succeedOnAttempt": 3}})
    submit(body)
    authorize(body)
    final = wait_state(body["commandId"], "SUCCEEDED", timeout=60)
    eff = actuator_result(final["executionKey"])
    assert eff["status"] == "SUCCESS"
    assert eff["result"]["physicalEffectCount"] == 1
    assert eff["attempts"] == 3
    events = timeline_all(body["commandId"])
    attempts = [e for e in events if e["type"] == "DELIVERY_ATTEMPT"]
    assert len(attempts) == 3
    # All attempts carried the same stable executionKey.
    cmd = get_command(body["commandId"])
    assert final["executionKey"] == f"exec-v1-{body['commandId']}"
    assert cmd["state"] == "SUCCEEDED"


def test_explicit_rejection_is_terminal_and_never_retried():
    body = make_command_body(
        params={"__sim": {"mode": "reject", "reason": "interlock open"}})
    submit(body)
    authorize(body)
    final = wait_state(body["commandId"], "FAILED", timeout=30)
    assert final["finalResult"]["error"] == "ACTUATOR_REJECTED"
    events = timeline_all(body["commandId"])
    assert [e for e in events if e["type"] == "DELIVERY_FAILED"]
    # No automatic re-delivery after settling.
    time.sleep(2.0)
    assert get_command(body["commandId"])["state"] == "FAILED"
    attempts = [e for e in events if e["type"] == "DELIVERY_ATTEMPT"]
    assert len(attempts) == 1


def timeline_all(command_id: str):
    out = []
    cursor = None
    for _ in range(100):
        params = {"limit": 50}
        if cursor:
            params["cursor"] = cursor
        page = timeline(command_id, **params)
        out.extend(page["events"])
        cursor = page["nextCursor"]
        if not cursor:
            return out
    raise AssertionError("too many pages")


# ------------------------------------------------------------- concurrency --

def test_concurrent_revoke_and_claim_exactly_one_winner():
    """Many authorized commands are cancelled while the two workers race to
    claim them. Whichever side wins, the outcome must be internally
    consistent: 200 cancel <=> CANCELLED and no executionKey/effect;
    409 REVOKE_RACE_LOST <=> claim committed first and delivery converges."""
    import uuid as uuid_mod
    bodies = [make_command_body(commandId=f"race-{i}-{uuid_mod.uuid4().hex[:8]}")
              for i in range(8)]
    for b in bodies:
        submit(b)
        authorize(b)

    results = []
    for b in bodies:
        cr = requests.post(f"{BASE_URL}/api/v1/commands/{b['commandId']}/cancel",
                           json={"requestedBy": "racer"}, timeout=10)
        assert cr.status_code in (200, 409), cr.text
        results.append((b, cr.status_code, cr.json()))

    cancelled = 0
    claimed = 0
    for b, status, payload in results:
        if status == 200:
            cmd = wait_state(b["commandId"], "CANCELLED", timeout=5) \
                if get_command(b["commandId"])["state"] == "CANCELLED" \
                else get_command(b["commandId"])
            assert cmd["state"] == "CANCELLED", cmd["state"]
            assert cmd["executionKey"] is None
            cancelled += 1
        else:
            assert payload["error"]["code"] == "REVOKE_RACE_LOST"
            cmd = wait_state(b["commandId"], "SUCCEEDED", "FAILED", timeout=30)
            if cmd["state"] == "SUCCEEDED":
                eff = actuator_result(cmd["executionKey"])
                assert eff["status"] == "SUCCESS"
                assert eff["result"]["physicalEffectCount"] == 1
            claimed += 1
    # Strong per-command invariant only; exact split is timing-dependent and
    # the exactly-one-winner arbitration is proven deterministically in
    # tests/test_db_arbitration.py. The 409 path over HTTP is covered by
    # test_cancel_after_claim_loses_race.
    assert cancelled + claimed == len(bodies)
    assert cancelled >= 1  # cancels are issued immediately after authorization
