"""Simulated substation station-end actuator (zero third-party dependencies).

Guarantees provided by THIS mock (the real downstream is assumed to offer the
same idempotency contract):

  * A stable `executionKey` identifies one logical physical operation.
  * The first accepted /execute call for a key performs the (simulated)
    physical effect EXACTLY ONCE and it is durably recorded BEFORE any
    response is written. A response that is then lost (client timeout,
    connection reset, caller crash) can therefore never cause a second
    physical effect: re-delivery with the same key returns the recorded
    result, and /result/{key} exposes the final outcome for recovery.
  * Unknown keys queried via /result answer 404 UNKNOWN: the caller has not
    yet observed acceptance, so it may safely retry /execute with that key.

Test behavior is controlled entirely by the optional `sim` object inside the
request (or forwarded command params):

  {"mode": "ok"}                       accept, succeed (default)
  {"mode": "reject", "reason": "..."}  explicit permanent rejection -> FAILED
  {"mode": "timeoutFirst",
   "delaySeconds": 30}                 record SUCCESS first, then stall on the
                                       FIRST /execute call only; later calls
                                       return the recorded success
  {"mode": "flaky", "succeedOnAttempt": 3}
                                       transient HTTP 500 (NO effect recorded)
                                       until attempt N, then accept & succeed
"""
from __future__ import annotations

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# key -> {"status": "SUCCESS"|"FAILED", "result": {...}, "at": ts, "attempts": n}
EFFECTS: dict[str, dict] = {}
# Transient attempts that produced no effect, so flaky simulations can count.
ATTEMPTS: dict[str, int] = {}
LOCK = threading.Lock()


def _json(handler: BaseHTTPRequestHandler, status: int, body: dict) -> None:
    raw = json.dumps(body).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class Handler(BaseHTTPRequestHandler):
    server_version = "MockActuator/1.0"

    def log_message(self, fmt, *args):  # quieter logs
        if os.environ.get("ACTUATOR_VERBOSE"):
            super().log_message(fmt, *args)

    def do_GET(self):
        if self.path == "/healthz":
            _json(self, 200, {"status": "ok"})
            return
        if self.path.startswith("/result/"):
            key = self.path[len("/result/"):]
            with LOCK:
                effect = EFFECTS.get(key)
            if effect is None:
                _json(self, 404, {"executionKey": key, "status": "UNKNOWN",
                                  "message": "never observed an accepted execute"})
            else:
                _json(self, 200, {"executionKey": key, **effect})
            return
        _json(self, 404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/execute":
            _json(self, 404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0"))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            _json(self, 400, {"error": "invalid json"})
            return

        key = body.get("executionKey")
        if not key:
            _json(self, 400, {"error": "executionKey required"})
            return
        sim = body.get("sim") or body.get("params", {}).get("__sim") or {}
        mode = sim.get("mode", "ok")

        with LOCK:
            existing = EFFECTS.get(key)
            if existing is not None:
                # Idempotent replay: the single physical effect is already in;
                # always answer with the recorded final result.
                _json(self, 200, {"executionKey": key, "replay": True, **existing})
                return

            if mode == "reject":
                # Explicit permanent refusal: recorded as final FAILED.
                EFFECTS[key] = {
                    "status": "FAILED",
                    "attempts": ATTEMPTS.get(key, 0) + 1,
                    "at": time.time(),
                    "result": {"rejected": True, "reason": sim.get("reason", "rejected")},
                }
                _json(self, 422, {"executionKey": key,
                                  **EFFECTS[key]})
                return

            if mode == "flaky":
                threshold = int(sim.get("succeedOnAttempt", 3))
                attempt = ATTEMPTS.get(key, 0) + 1
                ATTEMPTS[key] = attempt
                if attempt < threshold:
                    # Transient failure with NO physical effect.
                    _json(self, 503, {"executionKey": key, "status": "TRANSIENT",
                                      "attempt": attempt,
                                      "message": "simulated transient outage"})
                    return
                EFFECTS[key] = {
                    "status": "SUCCESS", "attempts": attempt, "at": time.time(),
                    "result": {"physicalEffectCount": 1, "attempts": attempt},
                }
                _json(self, 200, {"executionKey": key, **EFFECTS[key]})
                return

            # Default ("ok") and "timeoutFirst": the physical effect is made
            # durable BEFORE we react to the requested behavior, so a lost
            # response still means exactly-one effect.
            EFFECTS[key] = {
                "status": "SUCCESS",
                "attempts": ATTEMPTS.get(key, 0) + 1,
                "at": time.time(),
                "result": {"physicalEffectCount": 1},
            }

        if mode == "timeoutFirst":
            delay = float(sim.get("delaySeconds", 30))
            time.sleep(delay)  # caller times out / disconnects; effect is safe
            # Client may be gone; ignore broken pipe.
            try:
                _json(self, 200, {"executionKey": key, **EFFECTS[key]})
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        _json(self, 200, {"executionKey": key, **EFFECTS[key]})


def main() -> None:
    port = int(os.environ.get("ACTUATOR_PORT", "8090"))
    server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"mock actuator listening on :{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
