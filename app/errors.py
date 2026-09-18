"""Stable machine-readable error codes (see README / API.md)."""
from __future__ import annotations

ERROR_CODES = {
    "VALIDATION_ERROR",
    "CONTENT_CONFLICT",
    "SIGNER_NOT_QUALIFIED",
    "INVALID_SIGNATURE",
    "KEY_DISABLED",
    "NOT_BEFORE_NOT_REACHED",
    "COMMAND_EXPIRED",
    "REVOKE_RACE_LOST",
    "TERMINAL_STATE_CONFLICT",
    "COMMAND_NOT_FOUND",
    "KEY_NOT_FOUND",
    "ROLE_ALREADY_SIGNED",
    "SUBMITTER_MUST_NOT_SIGN",
    "DUPLICATE_SUBJECT_ROLE",
    "POLICY_REJECTION",
    "ACTUATOR_REJECTED",
    "CURSOR_INVALID",
    "INTERNAL_ERROR",
}


class APIError(Exception):
    def __init__(self, code: str, message: str, status_code: int = 400):
        if code not in ERROR_CODES:
            raise ValueError(f"undeclared error code: {code}")
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code


# Convenience constructors with their conventional HTTP statuses.
def not_found(code: str, message: str) -> APIError:
    return APIError(code, message, status_code=404)


def conflict(code: str, message: str) -> APIError:
    return APIError(code, message, status_code=409)


def unprocessable(code: str, message: str) -> APIError:
    return APIError(code, message, status_code=422)
