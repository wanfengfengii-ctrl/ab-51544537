#!/usr/bin/env python3
"""Client-side helper demonstrating the documented deterministic signature.

This is EXAMPLE code (not part of the service trust boundary): it shows how a
caller builds the exact signing bytes from app/canonical.py and produces the
base64 Ed25519 signature expected by POST /api/v1/commands/{id}/sign.

Usage (inside the image, where deps exist):
    python scripts/sign_helper.py genkey                # prints a PEM keypair
    python scripts/sign_helper.py sign <priv_pem_path> <command.json> OPERATOR 7

<command.json> is the exact JSON body submitted to POST /api/v1/commands.
"""
from __future__ import annotations

import base64
import json
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from app.canonical import command_canonical, signature_message  # noqa: E402


def _parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def main(argv: list[str]) -> int:
    cmd_name = argv[1] if len(argv) > 1 else ""
    if cmd_name == "genkey":
        priv = Ed25519PrivateKey.generate()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        print("# private (keep secret):")
        print(priv_pem)
        print("# public (register via POST /api/v1/keys):")
        print(pub_pem)
        return 0

    if cmd_name == "sign" and len(argv) == 6:
        priv_pem = Path(argv[2]).read_text()
        body = json.loads(Path(argv[3]).read_text())
        role = argv[4]
        policy_version = int(argv[5])
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None)
        canonical = command_canonical(
            command_id=body["commandId"], station=body["station"],
            device=body["device"], action=body["action"], params=body["params"],
            not_before=_parse_ts(body["notBefore"]),
            expires_at=_parse_ts(body["expiresAt"]),
            payload_version=body["payloadVersion"])
        message = signature_message(canonical, policy_version, role)
        print(base64.b64encode(priv.sign(message)).decode())
        return 0

    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
