"""Persistence layer. Every concurrency decision lives in a single database
transaction (row locks / conditional UPDATEs / unique constraints) so that any
number of API and worker processes arbitrate identically. No in-memory locks
and no local clock participate in state decisions: database now() is used.
"""
from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any

import psycopg

from .canonical import command_canonical, signature_message
from .db import jsonb
from .errors import APIError, conflict, not_found, unprocessable

ROLES = ("OPERATOR", "SAFETY")
TERMINAL_STATES = {"SUCCEEDED", "FAILED", "CANCELLED", "EXPIRED"}
# States after which revoke must never appear to succeed.
PAST_CLAIM_STATES = {"CLAIMED", "EXECUTING", "SUCCEEDED", "FAILED"}


def _now(conn) -> datetime:
    return conn.execute("SELECT now()").fetchone()["now"]


def add_event(conn, command_id: str, event_key: str, event_type: str,
              data: dict[str, Any] | None = None) -> None:
    """Append an audit event. (command_id, event_key) makes replay a no-op:
    a crashed-and-restarted delivery step can never duplicate an event."""
    conn.execute(
        "INSERT INTO audit_events (command_id, event_key, type, data) "
        "VALUES (%s, %s, %s, %s) ON CONFLICT (command_id, event_key) "
        "DO NOTHING",
        (command_id, event_key, event_type, jsonb(data or {})),
    )


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def serialize_key(row) -> dict[str, Any]:
    return {
        "keyId": row["key_id"],
        "subject": row["subject"],
        "role": row["role"],
        "publicKeyPem": row["public_key_pem"],
        "enabled": row["enabled"],
        "createdAt": _iso(row["created_at"]),
        "disabledAt": _iso(row["disabled_at"]),
    }


def serialize_command(row, roles: list[str], timeline: list[dict] | None = None,
                      page: dict | None = None) -> dict[str, Any]:
    out = {
        "commandId": row["command_id"],
        "submitter": row["submitter"],
        "station": row["station"],
        "device": row["device"],
        "action": row["action"],
        "params": row["params"],
        "notBefore": _iso(row["not_before"]),
        "expiresAt": _iso(row["expires_at"]),
        "payloadVersion": row["payload_version"],
        "policyVersion": row["policy_version"],
        "policySnapshot": row["policy_snapshot"],
        "state": row["state"],
        "satisfiedRoles": roles,
        # Execution key exists only once the claim boundary has been crossed.
        "executionKey": row["execution_key"] if row["execution_key"] else None,
        "finalResult": row["final_result"],
        "finalAt": _iso(row["final_at"]),
        "createdAt": _iso(row["created_at"]),
        "updatedAt": _iso(row["updated_at"]),
    }
    if timeline is not None:
        out["timeline"] = timeline
        out["timelinePage"] = page
    return out


def serialize_event(row) -> dict[str, Any]:
    return {
        "eventId": row["id"],
        "type": row["type"],
        "data": row["data"],
        "createdAt": _iso(row["created_at"]),
    }


# ---------------------------------------------------------------- keys ----

def register_key(conn, pem: str, subject: str, role: str) -> dict[str, Any]:
    if role not in ROLES:
        raise unprocessable("VALIDATION_ERROR", "role must be OPERATOR or SAFETY")
    if not subject:
        raise unprocessable("VALIDATION_ERROR", "subject is required")
    if not _is_ed25519_public_key(pem):
        raise unprocessable(
            "VALIDATION_ERROR",
            "publicKeyPem must be a PEM-encoded Ed25519 SPKI public key",
        )
    try:
        row = conn.execute(
            "INSERT INTO signing_keys (public_key_pem, subject, role) "
            "VALUES (%s, %s, %s) RETURNING *",
            (pem, subject, role),
        ).fetchone()
    except psycopg.UniqueViolation:
        raise conflict("CONTENT_CONFLICT", "this public key is already registered")
    conn.commit()
    return serialize_key(row)


def disable_key(conn, key_id: int) -> dict[str, Any]:
    # Database time stamps the disablement; later signature attempts compare
    # their transaction time against it.
    row = conn.execute(
        "UPDATE signing_keys SET enabled = FALSE, disabled_at = now() "
        "WHERE key_id = %s RETURNING *",
        (key_id,),
    ).fetchone()
    if row is None:
        conn.rollback()
        raise not_found("KEY_NOT_FOUND", f"key {key_id} not found")
    conn.commit()
    return serialize_key(row)


def get_key(conn, key_id: int) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM signing_keys WHERE key_id = %s",
                       (key_id,)).fetchone()
    if row is None:
        raise not_found("KEY_NOT_FOUND", f"key {key_id} not found")
    return serialize_key(row)


# ------------------------------------------------------------- commands ----

def submit_command(conn, payload: dict[str, Any]) -> dict[str, Any]:
    canonical = command_canonical(
        command_id=payload["commandId"],
        station=payload["station"],
        device=payload["device"],
        action=payload["action"],
        params=payload["params"],
        not_before=payload["notBefore"],
        expires_at=payload["expiresAt"],
        payload_version=payload["payloadVersion"],
    )
    policy = conn.execute(
        "SELECT version, body FROM policies WHERE active = TRUE ORDER BY version DESC LIMIT 1"
    ).fetchone()
    if policy is None:
        raise APIError("POLICY_REJECTION", "no active authorization policy", 503)

    try:
        row = conn.execute(
            "INSERT INTO commands (command_id, submitter, station, device, "
            "action, params, not_before, expires_at, payload_version, "
            "content_canonical, policy_version, policy_snapshot, state) "
            "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'PENDING') RETURNING *",
            (
                payload["commandId"], payload["submitter"], payload["station"],
                payload["device"], payload["action"], jsonb(payload["params"]),
                payload["notBefore"], payload["expiresAt"],
                payload["payloadVersion"], canonical, policy["version"],
                jsonb(policy["body"]),
            ),
        ).fetchone()
    except psycopg.UniqueViolation:
        conn.rollback()
        return _handle_duplicate_submit(conn, payload, canonical)

    add_event(conn, row["command_id"], "submit", "COMMAND_SUBMITTED", {
        "by": payload["submitter"], "policyVersion": policy["version"],
    })
    conn.commit()
    return serialize_command(row, [])


def _handle_duplicate_submit(conn, payload, canonical: bytes) -> dict[str, Any]:
    """Same commandId + byte-identical canonical content => replay returns the
    original command. Same commandId, different content => stable 409."""
    row = conn.execute("SELECT * FROM commands WHERE command_id = %s FOR SHARE",
                       (payload["commandId"],)).fetchone()
    if bytes(row["content_canonical"]) != canonical:
        raise conflict(
            "CONTENT_CONFLICT",
            "commandId already exists with different immutable content",
        )
    roles = _satisfied_roles(conn, row["command_id"])
    return serialize_command(row, roles)


def _satisfied_roles(conn, command_id: str) -> list[str]:
    rows = conn.execute(
        "SELECT role FROM signatures WHERE command_id = %s", (command_id,)
    ).fetchall()
    return sorted(r["role"] for r in rows)


def get_command(conn, command_id: str) -> dict[str, Any]:
    row = conn.execute("SELECT * FROM commands WHERE command_id = %s",
                       (command_id,)).fetchone()
    if row is None:
        raise not_found("COMMAND_NOT_FOUND", f"command {command_id} not found")
    roles = _satisfied_roles(conn, command_id)
    # Embed the first immutable timeline page (upper bound fixed at this read).
    page = _timeline_page(conn, command_id, limit=50, after_id=0)
    return serialize_command(row, roles, page["events"], page["page"])


def delivery_eligibility(conn, command_id: str) -> dict[str, Any]:
    """Read-only delivery-window check judged by database time. Returns a
    machine code; also performs the expiry transition when due."""
    cmd = conn.execute(
        "SELECT * FROM commands WHERE command_id = %s FOR UPDATE",
        (command_id,),
    ).fetchone()
    if cmd is None:
        conn.rollback()
        raise not_found("COMMAND_NOT_FOUND", f"command {command_id} not found")
    now = _now(conn)
    code = "DELIVERABLE"
    if cmd["state"] in ("PENDING", "AUTHORIZED") and cmd["expires_at"] <= now:
        _expire_locked(conn, cmd, now)
        code = "COMMAND_EXPIRED"
    elif cmd["state"] == "PENDING":
        code = "PENDING_SIGNATURES"
    elif cmd["state"] == "AUTHORIZED" and cmd["not_before"] > now:
        code = "NOT_BEFORE_NOT_REACHED"
    elif cmd["state"] in ("CLAIMED", "EXECUTING"):
        code = "ALREADY_CLAIMED"
    elif cmd["state"] in TERMINAL_STATES:
        code = f"TERMINAL_{cmd['state']}"
    conn.commit()
    row = conn.execute("SELECT * FROM commands WHERE command_id = %s",
                       (command_id,)).fetchone()
    return {"commandId": command_id, "state": row["state"],
            "eligibility": code, "databaseTime": _iso(now)}


# ------------------------------------------------------------- signing ----

def sign_command(conn, command_id: str, role: str, subject: str,
                 pem: str, signature_b64: str) -> dict[str, Any]:
    if role not in ROLES:
        raise unprocessable("VALIDATION_ERROR", "role must be OPERATOR or SAFETY")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception:
        raise unprocessable("VALIDATION_ERROR", "signature must be base64")

    try:
        return _sign_tx(conn, command_id, role, subject, pem, signature)
    except psycopg.Error:
        conn.rollback()
        raise


def _sign_tx(conn, command_id, role, subject, pem, signature) -> dict[str, Any]:
    now = _now(conn)
    cmd = conn.execute(
        "SELECT * FROM commands WHERE command_id = %s FOR UPDATE",
        (command_id,),
    ).fetchone()
    if cmd is None:
        raise not_found("COMMAND_NOT_FOUND", f"command {command_id} not found")

    if cmd["expires_at"] <= now and cmd["state"] in ("PENDING", "AUTHORIZED"):
        _expire_locked(conn, cmd, now)
        conn.commit()
        raise conflict("COMMAND_EXPIRED", "command has passed expiresAt")

    if cmd["state"] in TERMINAL_STATES or cmd["state"] in PAST_CLAIM_STATES:
        raise conflict(
            "TERMINAL_STATE_CONFLICT",
            f"cannot sign a command in state {cmd['state']}",
        )

    key = conn.execute(
        "SELECT * FROM signing_keys WHERE public_key_pem = %s FOR SHARE", (pem,)
    ).fetchone()
    if key is None:
        raise unprocessable(
            "SIGNER_NOT_QUALIFIED",
            "public key is not registered; register it before signing",
        )

    # An already-recorded, byte-identical signing request is an idempotent
    # replay and succeeds EVEN IF the key has since been disabled: recorded
    # signatures survive disablement. It also creates no new timeline event.
    existing = conn.execute(
        "SELECT * FROM signatures WHERE command_id = %s AND role = %s",
        (command_id, role),
    ).fetchone()
    if existing is not None:
        same = (
            existing["subject"] == subject
            and existing["key_id"] == key["key_id"]
            and bytes(existing["signature"]) == signature
        )
        if same:
            conn.commit()
            return get_command(conn, command_id)
        raise conflict(
            "CONTENT_CONFLICT",
            f"role {role} is already held by another signature on this command",
        )

    # From here this is a NEW signature: key validity is judged entirely in
    # the database at database time — enabled flag, disablement stamp,
    # ownership and role. Disablement after this point cannot invalidate it.
    if not key["enabled"] or (key["disabled_at"] is not None
                              and key["disabled_at"] <= now):
        raise conflict("KEY_DISABLED", "signing key was disabled before this signing")
    if key["subject"] != subject or key["role"] != role:
        raise unprocessable(
            "SIGNER_NOT_QUALIFIED",
            "key does not belong to this subject/role combination",
        )
    if subject == cmd["submitter"]:
        raise unprocessable(
            "SUBMITTER_MUST_NOT_SIGN",
            "the submitter of a command may not sign it",
        )

    message = signature_message(bytes(cmd["content_canonical"]),
                                cmd["policy_version"], role)
    if not _verify_ed25519(pem, signature, message):
        raise unprocessable("INVALID_SIGNATURE", "Ed25519 verification failed")

    other_role = conn.execute(
        "SELECT 1 FROM signatures WHERE command_id = %s AND subject = %s",
        (command_id, subject),
    ).fetchone()
    if other_role is not None:
        raise conflict(
            "DUPLICATE_SUBJECT_ROLE",
            "one subject may not occupy both OPERATOR and SAFETY roles",
        )

    try:
        conn.execute(
            "INSERT INTO signatures (command_id, role, subject, key_id, "
            "signature, signed_policy_version) VALUES (%s,%s,%s,%s,%s,%s)",
            (command_id, role, subject, key["key_id"], signature,
             cmd["policy_version"]),
        )
    except psycopg.UniqueViolation:
        # Lost a concurrent insert for this role / subject.
        raise conflict("CONTENT_CONFLICT", "concurrent conflicting signature")

    add_event(conn, command_id, f"sig:{role}", "SIGNATURE_ACCEPTED", {
        "role": role, "subject": subject, "keyId": key["key_id"],
        "policyVersion": cmd["policy_version"],
    })

    roles = _satisfied_roles(conn, command_id)
    if set(roles) == set(ROLES) and cmd["state"] == "PENDING":
        conn.execute(
            "UPDATE commands SET state = 'AUTHORIZED', updated_at = now() "
            "WHERE command_id = %s AND state = 'PENDING'",
            (command_id,),
        )
        add_event(conn, command_id, "authorized", "COMMAND_AUTHORIZED",
                  {"roles": sorted(ROLES)})
    conn.commit()
    return get_command(conn, command_id)


def _verify_ed25519(pem: str, signature: bytes, message: bytes) -> bool:
    # Imported lazily so migration-only tooling doesn't need the crypto dep.
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        pub = load_pem_public_key(pem.encode("utf-8"))
        if not isinstance(pub, Ed25519PublicKey):
            return False
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _is_ed25519_public_key(pem: str) -> bool:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    try:
        return isinstance(load_pem_public_key(pem.encode("utf-8")),
                          Ed25519PublicKey)
    except (ValueError, TypeError):
        return False


# ------------------------------------------------------------- cancel ------

def cancel_command(conn, command_id: str, requested_by: str | None,
                   reason: str | None) -> dict[str, Any]:
    cmd = conn.execute(
        "SELECT * FROM commands WHERE command_id = %s FOR UPDATE", (command_id,)
    ).fetchone()
    if cmd is None:
        raise not_found("COMMAND_NOT_FOUND", f"command {command_id} not found")

    if cmd["state"] == "CANCELLED":
        # Idempotent replay.
        conn.commit()
        return get_command(conn, command_id)
    if cmd["state"] in PAST_CLAIM_STATES:
        # The claim transaction committed first: revoke must not fake success.
        raise conflict(
            "REVOKE_RACE_LOST",
            f"delivery already claimed (state {cmd['state']}); revoke lost the race",
        )
    now = _now(conn)
    if cmd["expires_at"] <= now:
        _expire_locked(conn, cmd, now)
        conn.commit()
        raise conflict("COMMAND_EXPIRED", "command has passed expiresAt")
    if cmd["state"] == "EXPIRED":
        raise conflict("COMMAND_EXPIRED", "command already expired")

    conn.execute(
        "UPDATE commands SET state = 'CANCELLED', final_at = now(), "
        "updated_at = now() WHERE command_id = %s",
        (command_id,),
    )
    add_event(conn, command_id, "revoked", "COMMAND_CANCELLED",
              {"by": requested_by, "reason": reason})
    conn.commit()
    return get_command(conn, command_id)


def _expire_locked(conn, cmd, now) -> None:
    """Caller holds FOR UPDATE on the command row."""
    if cmd["state"] in ("PENDING", "AUTHORIZED") and cmd["expires_at"] <= now:
        conn.execute(
            "UPDATE commands SET state = 'EXPIRED', final_at = now(), "
            "updated_at = now() WHERE command_id = %s",
            (cmd["command_id"],),
        )
        add_event(conn, cmd["command_id"], "expired", "COMMAND_EXPIRED",
                  {"expiresAt": _iso(cmd["expires_at"])})


def scan_expirations(conn) -> int:
    """Worker-side sweep; the conditional update makes concurrent sweeps safe."""
    now = _now(conn)
    rows = conn.execute(
        "SELECT * FROM commands WHERE state IN ('PENDING','AUTHORIZED') "
        "AND expires_at <= %s ORDER BY expires_at FOR UPDATE SKIP LOCKED",
        (now,),
    ).fetchall()
    for cmd in rows:
        _expire_locked(conn, cmd, now)
    conn.commit()
    return len(rows)


# --------------------------------------------------------------- claim -----

def claim_due_command(conn, worker_id: str, lease_seconds: int):
    """Atomically win the right to deliver one command.

    Selects either an AUTHORIZED command inside its delivery window, or a
    CLAIMED command whose previous holder's lease expired (crash recovery),
    then conditionally flips/keeps state in one statement. FOR UPDATE SKIP
    LOCKED guarantees at most one worker wins each race; the row is locked
    until commit, so a concurrent revoke blocks then sees CLAIMED and fails
    with REVOKE_RACE_LOST.
    """
    row = conn.execute(
        """
        WITH picked AS (
            SELECT command_id, state AS old_state,
                   lease_owner AS old_owner, lease_epoch AS old_epoch
            FROM commands
            WHERE
              (state = 'AUTHORIZED'
                 AND not_before <= now()
                 AND expires_at > now())
              OR
              (state IN ('CLAIMED', 'EXECUTING')
                 AND lease_expires_at IS NOT NULL
                 AND lease_expires_at <= now())
              OR
              -- A retry whose backoff elapsed: the current lease owner may
              -- take it immediately; anyone else must wait for lease expiry,
              -- so two workers never run the same retry concurrently.
              (state IN ('CLAIMED', 'EXECUTING')
                 AND next_retry_at IS NOT NULL
                 AND next_retry_at <= now()
                 AND (lease_owner = %(worker)s OR lease_expires_at <= now()))
            ORDER BY not_before, command_id
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        UPDATE commands c
        SET state = 'CLAIMED',
            lease_owner = %(worker)s,
            lease_expires_at = now() + (%(lease)s || ' seconds')::interval,
            lease_epoch = c.lease_epoch + 1,
            next_retry_at = NULL,
            -- Stable key: derived from commandId and never regenerated.
            execution_key = COALESCE(c.execution_key,
                                     'exec-v1-' || c.command_id),
            updated_at = now()
        FROM picked
        WHERE c.command_id = picked.command_id
        RETURNING c.*, picked.old_state, picked.old_owner, picked.old_epoch
        """,
        {"worker": worker_id, "lease": lease_seconds},
    ).fetchone()
    if row is not None:
        # A CLAIMED business event marks the atomic delivery boundary: the
        # first transition AUTHORIZED -> CLAIMED, OR a genuine crash/lease
        # handoff to a different owner. A worker merely resuming after its own
        # configured backoff is the same delivery attempt lineage and must not
        # manufacture another business event.
        first_claim = row["old_state"] == "AUTHORIZED"
        handoff = (row["old_owner"] is not None
                   and row["old_owner"] != worker_id)
        if first_claim or handoff:
            add_event(conn, row["command_id"], f"claim:{row['lease_epoch']}",
                      "DELIVERY_CLAIMED", {
                "worker": worker_id,
                "leaseEpoch": row["lease_epoch"],
                "executionKey": row["execution_key"],
                "recovery": (not first_claim) or row["delivery_attempts"] > 0,
                "handoffFrom": None if first_claim else row["old_owner"],
            })
        conn.commit()
    return row


def record_attempt(conn, command_id: str, attempt_no: int, phase: str,
                   detail: dict[str, Any], worker_id: str) -> bool:
    """Returns False (and records nothing) if the caller no longer owns an
    active lease (lease expired and another worker took over) or the command
    is already terminal. A late zombie worker can therefore never regress
    SUCCEEDED/FAILED back into delivery."""
    cur = conn.execute(
        "UPDATE commands SET delivery_attempts = %s, state = 'EXECUTING', "
        "updated_at = now() WHERE command_id = %s AND lease_owner = %s "
        "AND state NOT IN ('SUCCEEDED','FAILED','CANCELLED','EXPIRED')",
        (attempt_no, command_id, worker_id),
    )
    if cur.rowcount == 0:
        conn.rollback()
        return False
    add_event(conn, command_id, f"attempt:{attempt_no}", "DELIVERY_ATTEMPT", {
        "attempt": attempt_no, "phase": phase, **detail,
    })
    conn.commit()
    return True


def record_recovery_query(conn, command_id: str, query_no: int,
                          outcome: str, detail: dict[str, Any],
                          worker_id: str) -> bool:
    owner = conn.execute(
        "SELECT state, lease_owner FROM commands WHERE command_id = %s",
        (command_id,),
    ).fetchone()
    if owner is None or owner["state"] in TERMINAL_STATES \
            or owner["lease_owner"] != worker_id:
        conn.rollback()
        return False
    add_event(conn, command_id, f"query:{query_no}", "RECOVERY_QUERY",
              {"query": query_no, "outcome": outcome, **detail})
    conn.commit()
    return True


def count_event_prefix(conn, command_id: str, prefix: str) -> int:
    return conn.execute(
        "SELECT count(*) AS n FROM audit_events WHERE command_id = %s "
        "AND event_key LIKE %s",
        (command_id, prefix + "%"),
    ).fetchone()["n"]


def get_command_row(conn, command_id: str):
    return conn.execute("SELECT * FROM commands WHERE command_id = %s",
                        (command_id,)).fetchone()


def schedule_retry(conn, command_id: str, worker_id: str, delay_seconds: float,
                   lease_seconds: int, attempt_no: int, reason: str) -> bool:
    # The lease is extended past the retry moment: a live worker keeps the
    # claim; if it dies, another worker takes over exactly at retry time.
    # Guarded by lease ownership so a zombie cannot schedule after takeover.
    cur = conn.execute(
        "UPDATE commands SET next_retry_at = now() + (%s || ' seconds')::interval, "
        "lease_expires_at = greatest("
        "  now() + (%s || ' seconds')::interval, "
        "  now() + (%s || ' seconds')::interval), updated_at = now() "
        "WHERE command_id = %s AND lease_owner = %s AND state NOT IN "
        "('SUCCEEDED','FAILED','CANCELLED','EXPIRED')",
        (delay_seconds, delay_seconds, lease_seconds * 2,
         command_id, worker_id),
    )
    if cur.rowcount == 0:
        conn.rollback()
        return False
    add_event(conn, command_id, f"retry-scheduled:{attempt_no}",
              "RETRY_SCHEDULED",
              {"delaySeconds": delay_seconds, "attempt": attempt_no,
               "reason": reason})
    conn.commit()
    return True


def resolve_terminal(conn, command_id: str, succeeded: bool,
                     result: dict[str, Any], origin: str) -> bool:
    """Convergent terminal transition. Returns False if the command was
    already terminal; in that case no extra terminal event is appended."""
    state = "SUCCEEDED" if succeeded else "FAILED"
    cur = conn.execute(
        "UPDATE commands SET state = %s, final_result = %s, final_at = now(), "
        "lease_owner = NULL, lease_expires_at = NULL, next_retry_at = NULL, "
        "updated_at = now() "
        "WHERE command_id = %s AND state NOT IN ('SUCCEEDED','FAILED',"
        "'CANCELLED','EXPIRED')",
        (state, jsonb(result), command_id),
    )
    if cur.rowcount == 0:
        conn.rollback()
        return False
    add_event(conn, command_id,
              "terminal-success" if succeeded else "terminal-failed",
              "DELIVERY_SUCCEEDED" if succeeded else "DELIVERY_FAILED",
              {"result": result, "origin": origin})
    conn.commit()
    return True


# -------------------------------------------------------------- timeline ---

_CURSOR_MAX_NEW = -1  # marker: first page, upper bound fixed inside


def encode_cursor(after_id: int, upper: int) -> str:
    raw = json.dumps({"after": after_id, "max": upper},
                     separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(token: str) -> tuple[int, int]:
    try:
        pad = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode(token + pad)
        data = json.loads(raw)
        return int(data["after"]), int(data["max"])
    except Exception:
        raise unprocessable("CURSOR_INVALID", "malformed pagination cursor")


def _timeline_page(conn, command_id: str, limit: int, after_id: int,
                   upper: int | None = None) -> dict[str, Any]:
    if upper is None:
        # First page of a view: fix an immutable upper bound for the whole
        # view. Events committed afterwards belong to a later view only, so
        # they cannot sneak into, duplicate, or push out old events.
        upper = conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS m FROM audit_events WHERE command_id = %s",
            (command_id,),
        ).fetchone()["m"]
    rows = conn.execute(
        "SELECT * FROM audit_events WHERE command_id = %s AND id > %s AND id <= %s "
        "ORDER BY id ASC LIMIT %s",
        (command_id, after_id, upper, limit + 1),
    ).fetchall()
    events = [serialize_event(r) for r in rows[:limit]]
    next_cursor = None
    if len(rows) > limit:
        next_cursor = encode_cursor(rows[limit - 1]["id"], upper)
    return {
        "events": events,
        "page": {"nextCursor": next_cursor, "viewUpperBoundEventId": upper},
    }


def fetch_timeline(conn, command_id: str, limit: int,
                   cursor: str | None) -> dict[str, Any]:
    if not 1 <= limit <= 200:
        raise unprocessable("VALIDATION_ERROR", "limit must be between 1 and 200")
    if conn.execute("SELECT 1 FROM commands WHERE command_id = %s",
                    (command_id,)).fetchone() is None:
        raise not_found("COMMAND_NOT_FOUND", f"command {command_id} not found")

    if cursor is None:
        page = _timeline_page(conn, command_id, limit, after_id=0)
    else:
        after_id, upper = decode_cursor(cursor)
        page = _timeline_page(conn, command_id, limit, after_id, upper)
    return page["page"] | {"events": page["events"]}
