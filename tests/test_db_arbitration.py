"""Deterministic concurrency tests at the transaction boundary.

These open multiple real Postgres connections and interleave repository
operations on barrier points, so they prove arbitration without depending on
worker polling timing.
"""
from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import psycopg
from psycopg.rows import dict_row
from urllib.parse import urlsplit, urlunsplit

from app import repository as repo
from app.config import settings

# These tests need to drive the state machine WITHOUT the live workers
# claiming their rows. They run against a separate database on the same
# Postgres server (no worker is connected to it), created on first use.
ARBIT_DB = "substation_arbit"


def _server_dsn(dbname: str) -> str:
    parts = urlsplit(settings.database_url)
    return urlunsplit((parts.scheme,
                       (parts.username and f"{parts.username}:{parts.password}@"
                        or "") + f"{parts.hostname}:{parts.port or 5432}",
                       f"/{dbname}", parts.query, parts.fragment))


_arbit_dsn: str | None = None


def _bootstrap() -> str:
    global _arbit_dsn
    if _arbit_dsn:
        return _arbit_dsn
    admin = _server_dsn("postgres")
    with psycopg.connect(admin, autocommit=True) as conn:
        exists = conn.execute("SELECT 1 FROM pg_database WHERE datname=%s",
                              (ARBIT_DB,)).fetchone()
        if not exists:
            conn.execute(f"CREATE DATABASE {ARBIT_DB}")
    dsn = _server_dsn(ARBIT_DB)
    with psycopg.connect(dsn, autocommit=True) as conn:
        for sql_file in sorted(
                (Path(__file__).resolve().parent.parent / "migrations").glob("*.sql")):
            conn.execute(sql_file.read_text())
    _arbit_dsn = dsn
    return dsn


def _conn():
    c = psycopg.connect(_bootstrap(), row_factory=dict_row)
    return c


def _insert_authorized_command(cid: str, *, due: bool = True) -> None:
    now = datetime.now(timezone.utc)
    nb = now - timedelta(seconds=5) if due else now + timedelta(hours=1)
    with _conn() as conn:
        # Natural-key helper keys; never specify key_id so the sequence stays
        # consistent for API-created rows.
        conn.execute(
            "INSERT INTO signing_keys (public_key_pem, subject, role) "
            "VALUES ('pem-op-arbit','alice','OPERATOR'),"
            "('pem-sf-arbit','bob','SAFETY') ON CONFLICT DO NOTHING")
        ids = {r["role"]: r["key_id"] for r in conn.execute(
            "SELECT key_id, role FROM signing_keys "
            "WHERE public_key_pem IN ('pem-op-arbit','pem-sf-arbit')")}
        conn.execute(
            "INSERT INTO commands (command_id, submitter, station, device, "
            "action, params, not_before, expires_at, payload_version, "
            "content_canonical, policy_version, policy_snapshot, state) "
            "VALUES (%s,'disp','s','d','OPEN','{}'::jsonb,%s,%s,1,'x',1,"
            "'{}'::jsonb,'AUTHORIZED')",
            (cid, nb, now + timedelta(hours=1)))
        conn.execute(
            "INSERT INTO signatures VALUES "
            "(%s,'OPERATOR','alice',%s,'x',1),(%s,'SAFETY','bob',%s,'x',1)",
            (cid, ids["OPERATOR"], cid, ids["SAFETY"]))
        conn.commit()


def test_claim_versus_cancel_exactly_one_wins():
    for i in range(10):
        cid = f"db-race-{i}-{threading.get_ident()}"
        _insert_authorized_command(cid)
        c_claim, c_cancel = _conn(), _conn()
        start = threading.Barrier(2)
        outcomes = {}

        def claimer():
            start.wait()
            try:
                # Same conditional statement the repository uses, filtered to
                # this command to keep the test deterministic.
                row = c_claim.execute(
                    "UPDATE commands SET state='CLAIMED', lease_owner='w1', "
                    "lease_expires_at=now() + interval '60 seconds', "
                    "execution_key=COALESCE(execution_key,'exec-v1-'||command_id) "
                    "WHERE command_id=%s AND state='AUTHORIZED' "
                    "AND not_before <= now() AND expires_at > now() "
                    "RETURNING *", (cid,)).fetchone()
                c_claim.commit()
                outcomes["claim"] = row is not None
            except Exception as exc:
                outcomes["claim"] = False
                c_claim.rollback()

        def canceller():
            start.wait()
            try:
                repo.cancel_command(c_cancel, cid, "u", None)
                outcomes["cancel"] = True
            except Exception:
                outcomes["cancel"] = False
                c_cancel.rollback()

        t1 = threading.Thread(target=claimer)
        t2 = threading.Thread(target=canceller)
        t1.start(); t2.start(); t1.join(); t2.join()
        assert outcomes["claim"] != outcomes["cancel"], outcomes
        with _conn() as check:
            state = check.execute(
                "SELECT state, execution_key FROM commands WHERE command_id=%s",
                (cid,)).fetchone()
            if outcomes["claim"]:
                assert state["state"] == "CLAIMED" and state["execution_key"]
            else:
                assert state["state"] == "CANCELLED" and not state["execution_key"]
        c_claim.close(); c_cancel.close()


def test_many_concurrent_claims_only_one_winner():
    cid = f"db-multi-{threading.get_ident()}"
    _insert_authorized_command(cid)
    n = 8
    barrier = threading.Barrier(n)
    winners = []
    lock = threading.Lock()

    def one(idx):
        conn = _conn()
        barrier.wait()
        try:
            row = conn.execute(
                "WITH picked AS ("
                "SELECT command_id FROM commands WHERE command_id=%s "
                "AND state='AUTHORIZED' AND not_before<=now() "
                "AND expires_at>now() FOR UPDATE SKIP LOCKED LIMIT 1) "
                "UPDATE commands c SET state='CLAIMED', lease_owner=%s, "
                "lease_expires_at=now()+interval '60 seconds', "
                "execution_key=COALESCE(c.execution_key,'exec-v1-'||c.command_id) "
                "FROM picked WHERE c.command_id=picked.command_id RETURNING c.*",
                (cid, f"w{idx}")).fetchone()
            conn.commit()
            if row:
                with lock:
                    winners.append(idx)
        except Exception:
            conn.rollback()
        finally:
            conn.close()

    threads = [threading.Thread(target=one, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert winners == [winners[0]] and len(winners) == 1, winners


def test_claim_after_commit_cancel_can_not_fake_success():
    cid = f"db-order-{threading.get_ident()}"
    _insert_authorized_command(cid)
    # Cancel wins first.
    with _conn() as conn:
        repo.cancel_command(conn, cid, "u", None)
    # A later worker claim must not pick the cancelled command at all.
    with _conn() as conn:
        row = conn.execute(
            "SELECT command_id FROM commands WHERE state='AUTHORIZED' "
            "AND not_before<=now() AND expires_at>now() "
            "AND command_id=%s FOR UPDATE SKIP LOCKED", (cid,)).fetchone()
        assert row is None
    # And a duplicate cancel is idempotent success without a new event.
    with _conn() as conn:
        before = conn.execute(
            "SELECT count(*) n FROM audit_events WHERE command_id=%s "
            "AND type='COMMAND_CANCELLED'", (cid,)).fetchone()["n"]
        repo.cancel_command(conn, cid, "u", None)
        after = conn.execute(
            "SELECT count(*) n FROM audit_events WHERE command_id=%s "
            "AND type='COMMAND_CANCELLED'", (cid,)).fetchone()["n"]
        assert before == after == 1


def _conn_commit(conn):  # pragma: no cover
    return conn
