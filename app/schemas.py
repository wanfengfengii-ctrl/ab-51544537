"""Request/response models for the versioned JSON API."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class RegisterKeyRequest(BaseModel):
    subject: str = Field(min_length=1, max_length=200)
    role: str
    publicKeyPem: str

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in ("OPERATOR", "SAFETY"):
            raise ValueError("role must be OPERATOR or SAFETY")
        return v

    @field_validator("publicKeyPem")
    @classmethod
    def _pem(cls, v: str) -> str:
        if "BEGIN PUBLIC KEY" not in v:
            raise ValueError("publicKeyPem must be a PEM-encoded SPKI public key")
        return v.strip()


class SubmitCommandRequest(BaseModel):
    commandId: str = Field(min_length=1, max_length=100)
    submitter: str = Field(min_length=1, max_length=200)
    station: str = Field(min_length=1, max_length=100)
    device: str = Field(min_length=1, max_length=100)
    action: str = Field(min_length=1, max_length=100)
    params: dict[str, Any] = Field(default_factory=dict)
    notBefore: datetime
    expiresAt: datetime
    payloadVersion: int = Field(gt=0)

    @field_validator("notBefore", "expiresAt")
    @classmethod
    def _tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamps must be timezone-aware (RFC 3339)")
        return v


class SignRequest(BaseModel):
    role: str
    subject: str = Field(min_length=1, max_length=200)
    publicKeyPem: str
    signature: str = Field(description="base64 Ed25519 signature over the documented bytes")

    @field_validator("role")
    @classmethod
    def _role(cls, v: str) -> str:
        if v not in ("OPERATOR", "SAFETY"):
            raise ValueError("role must be OPERATOR or SAFETY")
        return v


class CancelRequest(BaseModel):
    requestedBy: str | None = None
    reason: str | None = None
