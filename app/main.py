"""Versioned HTTP JSON API (prefix /api/v1).

The API is stateless: all authorization and state arbitration happens in the
database, so any number of replicas behave identically.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from . import repository as repo
from . import db
from .db import init_pool, run_migrations, wait_for_database
from .errors import APIError
from .schemas import (CancelRequest, RegisterKeyRequest, SignRequest,
                      SubmitCommandRequest)

log = logging.getLogger("api")


@asynccontextmanager
async def lifespan(app: FastAPI):
    wait_for_database()
    run_migrations()
    init_pool()
    yield
    if db.pool is not None:
        db.pool.close()


app = FastAPI(title="Substation Remote Switching Service", version="1",
              lifespan=lifespan)


@app.exception_handler(APIError)
async def api_error_handler(request: Request, exc: APIError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
    )


@app.exception_handler(RequestValidationError)
async def validation_handler(request: Request,
                             exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": {
            "code": "VALIDATION_ERROR",
            "message": "request failed schema validation",
            "details": jsonable_encoder(exc.errors()),
        }},
    )


@app.exception_handler(Exception)
async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error")
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_ERROR", "message": "internal error"}},
    )


@app.get("/healthz")
def healthz() -> dict[str, str]:
    # Simple liveness; readiness is checked against /readyz.
    return {"status": "ok"}


@app.get("/readyz")
def readyz() -> JSONResponse:
    try:
        with db.pool.connection() as conn:
            conn.execute("SELECT 1")
        return JSONResponse({"status": "ready"})
    except Exception:
        return JSONResponse({"status": "not-ready"}, status_code=503)


@app.get("/api/v1/signing-format")
def signing_format() -> dict[str, str]:
    """Public, self-describing documentation pointer for the deterministic
    signature byte format (full specification in app/canonical.py / API.md)."""
    return {
        "commandMagic": "SUBSTATION-CMD-v1",
        "signatureMagic": "SUBSTATION-CMD-SIG-v1",
        "spec": "length-prefixed UTF-8 segments: 'name:<decimal byte "
                "length>:<raw bytes>\\n'; see API.md 'Deterministic signature "
                "format' for the authoritative segment order",
        "fields": ["commandId", "station", "device", "action", "params",
                   "notBefore", "expiresAt", "payloadVersion"],
        "signatureExtra": ["policyVersion", "role"],
        "canonicalParamsJson": "UTF-8, sorted object keys, no whitespace, "
                               "ensure_ascii=false; no JSON key-order dependence",
        "algorithm": "Ed25519 over the exact signature message bytes",
    }


# --------------------------------------------------------------- keys ------

@app.post("/api/v1/keys", status_code=201)
def register_key(body: RegisterKeyRequest) -> dict:
    with db.pool.connection() as conn:
        return repo.register_key(conn, body.publicKeyPem, body.subject, body.role)


@app.post("/api/v1/keys/{key_id}/disable", status_code=200)
def disable_key(key_id: int) -> dict:
    with db.pool.connection() as conn:
        return repo.disable_key(conn, key_id)


@app.get("/api/v1/keys/{key_id}")
def get_key(key_id: int) -> dict:
    with db.pool.connection() as conn:
        return repo.get_key(conn, key_id)


# ------------------------------------------------------------ commands -----

@app.post("/api/v1/commands", status_code=201)
def submit_command(body: SubmitCommandRequest) -> dict:
    with db.pool.connection() as conn:
        return repo.submit_command(conn, body.model_dump())


@app.get("/api/v1/commands/{command_id}")
def get_command(command_id: str) -> dict:
    with db.pool.connection() as conn:
        return repo.get_command(conn, command_id)


@app.get("/api/v1/commands/{command_id}/delivery-eligibility")
def delivery_eligibility(command_id: str) -> dict:
    with db.pool.connection() as conn:
        return repo.delivery_eligibility(conn, command_id)


@app.post("/api/v1/commands/{command_id}/sign")
def sign_command(command_id: str, body: SignRequest) -> dict:
    with db.pool.connection() as conn:
        return repo.sign_command(
            conn, command_id, body.role, body.subject,
            body.publicKeyPem.strip(), body.signature,
        )


@app.post("/api/v1/commands/{command_id}/cancel")
def cancel_command(command_id: str, body: CancelRequest) -> dict:
    with db.pool.connection() as conn:
        return repo.cancel_command(conn, command_id, body.requestedBy,
                                   body.reason)


@app.get("/api/v1/commands/{command_id}/timeline")
def timeline(
    command_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
) -> dict:
    with db.pool.connection() as conn:
        return repo.fetch_timeline(conn, command_id, limit, cursor)
