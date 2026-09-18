"""Independent delivery worker.

Runs as its own process (multiple replicas allowed). The HTTP request path
never performs delivery. Correctness comes from the database, not memory:

  * Claiming is one conditional UPDATE ... FOR UPDATE SKIP LOCKED tx. At most
    one worker wins each command; a concurrent revoke loses after claim commit.
  * The executionKey is stable (derived from commandId) and generated at claim
    time. It is NEVER regenerated: a crashed/retried delivery keeps the same
    key, and the actuator guarantees one physical effect per key.
  * Before (re)sending after an interrupted attempt, the worker queries the
    actuator by executionKey. "Accepted but response lost" therefore converges
    to the recorded terminal result instead of being blindly re-posted.
    (Re-posting with the same key would also be safe thanks to idempotency;
    the query additionally resolves cases where the actuator is still holding
    a slow in-flight execution.)
"""
from __future__ import annotations

import json
import logging
import os
import socket
import time
import urllib.error
import urllib.request
import uuid

from app import repository as repo
from app.config import settings
from app.db import init_pool, wait_for_database

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s worker %(message)s")
log = logging.getLogger("worker")

WORKER_ID = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex[:8]}"


class ActuatorError(Exception):
    def __init__(self, kind: str, status: int | None, detail: str):
        super().__init__(detail)
        self.kind = kind            # "transient" | "rejected"
        self.status = status
        self.detail = detail


def _http_post(url: str, body: dict, timeout: float) -> dict:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", "replace")
        if exc.code in (408, 425, 429) or 500 <= exc.code <= 599:
            raise ActuatorError("transient", exc.code, text)
        # 4xx other than 408/425/429 is an explicit, permanent refusal.
        raise ActuatorError("rejected", exc.code, text)
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise ActuatorError("transient", None, str(exc))


def _http_get(url: str, timeout: float) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read().decode("utf-8", "replace"))
        except Exception:
            return exc.code, None
    except (urllib.error.URLError, TimeoutError, OSError):
        return 0, None


def query_result(execution_key: str) -> tuple[str, dict | None]:
    """Returns ('SUCCESS'|'FAILED'|'UNKNOWN'|'UNREACHABLE', body)."""
    status, body = _http_get(
        f"{settings.actuator_url}/result/{execution_key}",
        settings.http_timeout_seconds,
    )
    if status == 200 and body:
        return body.get("status", "UNKNOWN"), body
    if status == 404:
        return "UNKNOWN", body
    return "UNREACHABLE", body


def backoff_delay(attempt_no: int) -> float:
    schedule = settings.backoff_seconds
    if attempt_no - 1 < len(schedule):
        return float(schedule[attempt_no - 1])
    return float(schedule[-1])


def handle_claim(conn, cmd) -> None:
    cid = cmd["command_id"]
    key = cmd["execution_key"]
    epoch = cmd["lease_epoch"]
    attempts = cmd["delivery_attempts"]
    log.info("claimed %s (epoch=%s attempts=%s key=%s)", cid, epoch, attempts, key)

    # Recovery: anything other than a pristine first claim means a previous
    # attempt may already have been accepted. Resolve through the SAME key.
    if attempts > 0:
        query_no = repo.count_event_prefix(conn, cid, "query:") + 1
        outcome, body = query_result(key)
        if not repo.record_recovery_query(conn, cid, query_no, outcome, {
                "worker": WORKER_ID, "httpStatus": "200/404"}, WORKER_ID):
            log.info("recovery of %s skipped: lease lost or terminal", cid)
            return
        if outcome == "SUCCESS":
            if repo.resolve_terminal(conn, cid, True,
                    body.get("result", {}) | {"via": "recovery-query"},
                    origin="recovery-query"):
                log.info("recovered %s as SUCCESS via result query", cid)
            return
        if outcome == "FAILED":
            if repo.resolve_terminal(conn, cid, False,
                    body.get("result", {}) | {"via": "recovery-query"},
                    origin="recovery-query"):
                log.info("recovered %s as FAILED via result query", cid)
            return
        # UNKNOWN / UNREACHABLE -> fall through to an idempotent re-POST.

    if attempts >= settings.max_attempts:
        repo.resolve_terminal(conn, cid, False, {
            "error": "MAX_ATTEMPTS_EXCEEDED",
            "attempts": attempts,
        }, origin="attempt-budget")
        return

    attempt_no = attempts + 1
    request_body = {
        "executionKey": key,
        "commandId": cid,
        "station": cmd["station"],
        "device": cmd["device"],
        "action": cmd["action"],
        "params": cmd["params"] or {},
        "payloadVersion": cmd["payload_version"],
    }
    if not repo.record_attempt(conn, cid, attempt_no, "send", {
            "worker": WORKER_ID, "leaseEpoch": epoch}, WORKER_ID):
        log.info("attempt %s on %s skipped: lease lost or terminal", attempt_no, cid)
        return

    try:
        resp = _http_post(f"{settings.actuator_url}/execute", request_body,
                          settings.http_timeout_seconds)
    except ActuatorError as exc:
        if exc.kind == "rejected":
            # Explicit downstream rejection: terminal, never auto-redelivered.
            if repo.resolve_terminal(conn, cid, False, {
                    "error": "ACTUATOR_REJECTED",
                    "httpStatus": exc.status,
                    "detail": exc.detail[:2000]},
                    origin=f"execute-attempt-{attempt_no}"):
                log.warning("command %s permanently rejected by actuator", cid)
            return
        # Transient / timeout / disconnect: acceptance is uncertain. Query the
        # final result using the SAME executionKey before any retry.
        query_no = repo.count_event_prefix(conn, cid, "query:") + 1
        outcome, body = query_result(key)
        if not repo.record_recovery_query(conn, cid, query_no, outcome, {
                "worker": WORKER_ID, "afterError": exc.detail[:500]}, WORKER_ID):
            log.info("post-error recovery of %s skipped: lease lost", cid)
            return
        if outcome == "SUCCESS":
            if repo.resolve_terminal(conn, cid, True,
                    body.get("result", {}) | {"via": "post-error-query"},
                    origin="post-error-query"):
                log.info("command %s succeeded; response had been lost", cid)
            return
        if outcome == "FAILED":
            repo.resolve_terminal(conn, cid, False,
                body.get("result", {}) | {"via": "post-error-query"},
                origin="post-error-query")
            return
        # Truly unknown: back off and retry with the same key.
        delay = backoff_delay(attempt_no)
        if repo.schedule_retry(conn, cid, WORKER_ID, delay,
                settings.delivery_lease_seconds, attempt_no,
                reason=exc.detail[:300]):
            log.info("command %s transient failure, retry in %ss", cid, delay)
        return

    status = resp.get("status")
    if status == "SUCCESS":
        if repo.resolve_terminal(conn, cid, True,
                resp.get("result", {}) | {"via": "execute",
                                          "replay": resp.get("replay", False)},
                origin=f"execute-attempt-{attempt_no}"):
            log.info("command %s delivered SUCCESS", cid)
    elif status == "FAILED":
        repo.resolve_terminal(conn, cid, False,
            resp.get("result", {}) | {"via": "execute"},
            origin=f"execute-attempt-{attempt_no}")
    else:
        # Unknown 2xx body: treat as transient and converge via query/retries.
        query_no = repo.count_event_prefix(conn, cid, "query:") + 1
        outcome, body = query_result(key)
        if not repo.record_recovery_query(conn, cid, query_no, outcome,
                {"worker": WORKER_ID, "afterStatus": status}, WORKER_ID):
            return
        if outcome in ("SUCCESS", "FAILED"):
            repo.resolve_terminal(conn, cid, outcome == "SUCCESS",
                (body or {}).get("result", {}), origin="post-status-query")
        else:
            delay = backoff_delay(attempt_no)
            repo.schedule_retry(conn, cid, WORKER_ID, delay,
                settings.delivery_lease_seconds, attempt_no,
                reason=f"unexpected status {status}")


def _heartbeat() -> None:
    # Container healthcheck watches this file's mtime; it is local liveness
    # only and never participates in delivery correctness.
    try:
        with open("/tmp/worker-heartbeat", "w") as fh:
            fh.write(str(time.time()))
    except OSError:
        pass


def run() -> None:
    wait_for_database()
    pool = init_pool(min_size=1, max_size=4)
    log.info("worker %s started; actuator=%s", WORKER_ID, settings.actuator_url)
    # Stagger replicas slightly to reduce first-poll collisions.
    time.sleep(uuid.uuid4().int % 20 / 100.0)
    while True:
        _heartbeat()
        try:
            with pool.connection() as conn:
                repo.scan_expirations(conn)
            with pool.connection() as conn:
                cmd = repo.claim_due_command(
                    conn, WORKER_ID, settings.delivery_lease_seconds)
            if cmd is None:
                time.sleep(settings.poll_seconds)
                continue
            with pool.connection() as conn:
                handle_claim(conn, cmd)
        except KeyboardInterrupt:
            raise
        except Exception as exc:  # keep the worker alive across DB blips
            log.warning("worker loop error: %r", exc)
            time.sleep(1.0)


if __name__ == "__main__":
    run()
