"""Postgres connection pool, migration runner and JSON helpers."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

import psycopg
from psycopg.rows import dict_row
from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from .config import settings

pool: ConnectionPool | None = None

MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"


def init_pool(min_size: int = 1, max_size: int = 10) -> ConnectionPool:
    global pool
    if pool is None:
        pool = ConnectionPool(
            settings.database_url,
            min_size=min_size,
            max_size=max_size,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=True,
        )
    return pool


def wait_for_database(timeout_seconds: float = 60.0) -> None:
    """Block until Postgres accepts TCP connections (used at startup)."""
    deadline = time.monotonic() + timeout_seconds
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(settings.database_url, autocommit=True,
                                 connect_timeout=3) as conn:
                conn.execute("SELECT 1")
            return
        except Exception as exc:  # pragma: no cover - startup retry path
            last = exc
            time.sleep(0.5)
    raise RuntimeError(f"database not ready: {last}")


def run_migrations() -> None:
    # Multiple API replicas start at once; serialize DDL with a transactional
    # advisory lock held for the whole migration pass.
    with psycopg.connect(settings.database_url, autocommit=True) as conn:
        with conn.transaction():
            conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations ("
                         "version TEXT PRIMARY KEY, applied_at TIMESTAMPTZ "
                         "NOT NULL DEFAULT now())")
            conn.execute("SELECT pg_advisory_xact_lock(91724803)")
            for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
                version = path.stem
                done = conn.execute(
                    "SELECT 1 FROM schema_migrations WHERE version = %s",
                    (version,),
                ).fetchone()
                if done:
                    continue
                conn.execute(path.read_text(encoding="utf-8"))
                conn.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s) "
                    "ON CONFLICT (version) DO NOTHING",
                    (version,),
                )
                print(f"applied migration {version}", flush=True)


def jsonb(value: Any) -> Jsonb:
    return Jsonb(value)
