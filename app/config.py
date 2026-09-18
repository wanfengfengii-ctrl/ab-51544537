"""Runtime configuration sourced from environment (12-factor)."""
from __future__ import annotations

import os
from dataclasses import dataclass


def _dsn() -> str:
    explicit = os.environ.get("DATABASE_URL")
    if explicit:
        return explicit
    return (
        f"postgresql://{os.environ.get('POSTGRES_USER', 'substation')}:"
        f"{os.environ.get('POSTGRES_PASSWORD', 'substation')}@"
        f"{os.environ.get('POSTGRES_HOST', 'db')}:5432/"
        f"{os.environ.get('POSTGRES_DB', 'substation')}"
    )


@dataclass(frozen=True)
class Settings:
    database_url: str = _dsn()
    actuator_url: str = os.environ.get("ACTUATOR_URL", "http://actuator:8090")
    # How long one worker may hold an exclusive delivery lease.
    delivery_lease_seconds: int = int(os.environ.get("DELIVERY_LEASE_SECONDS", "60"))
    # Backoff schedule for transient downstream errors.
    backoff_seconds: tuple[int, ...] = tuple(
        int(x) for x in os.environ.get("BACKOFF_SECONDS", "1,2,5,10,30").split(",")
    )
    max_attempts: int = int(os.environ.get("MAX_ATTEMPTS", "20"))
    http_timeout_seconds: float = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "5"))
    poll_seconds: float = float(os.environ.get("POLL_SECONDS", "0.5"))


settings = Settings()
