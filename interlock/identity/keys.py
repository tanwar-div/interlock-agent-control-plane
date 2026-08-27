"""Key management and detached signatures.

Interlock signs two different things:

  * action proposals, signed by the proposing agent, so that the governance
    plane can prove which agent asked for a change; and
  * ledger entries, signed by the control plane, so that an auditor can prove
    the record was not edited after the fact.

Ed25519 is used throughout: small keys, deterministic signatures, no parameter
choices to get wrong.
"""
from __future__ import annotations

import base64
import functools
import logging
import os
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from interlock.common.config import get_settings

logger = logging.getLogger(__name__)

_LOCAL_KEY_DIR = Path(os.environ.get("INTERLOCK_KEY_DIR", ".interlock-keys"))


def generate_keypair() -> tuple[str, str]:
    """Return (private_pem, public_pem) for a fresh Ed25519 keypair."""
    private = Ed25519PrivateKey.generate()
    private_pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def load_private_key(pem: str) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem.encode(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError("expected an Ed25519 private key")
    return key


def load_public_key(pem: str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem.encode())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    return key


def sign(private_pem: str, message: str) -> str:
    signature = load_private_key(private_pem).sign(message.encode("utf-8"))
    return base64.b64encode(signature).decode()


def verify(public_pem: str, message: str, signature_b64: str) -> bool:
    try:
        load_public_key(public_pem).verify(
            base64.b64decode(signature_b64), message.encode("utf-8")
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _secret_manager_pem(secret_id: str) -> str | None:
    """Fetch the control-plane signing key from Secret Manager.

    Returning None lets the caller fall back to a local key, which is what
    happens during local development.
    """
    settings = get_settings()
    if not settings.project_id:
        return None
    try:
        from google.cloud import secretmanager

        client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{settings.project_id}/secrets/{secret_id}/versions/latest"
        return client.access_secret_version(request={"name": name}).payload.data.decode()
    except Exception as exc:  # noqa: BLE001 - fall back rather than fail startup
        logger.warning("could not read signing key from Secret Manager (%s); using local key", exc)
        return None


@functools.lru_cache(maxsize=8)
def control_plane_key(secret_id: str | None = None) -> tuple[str, str]:
    """Return the control plane's (private_pem, public_pem).

    Resolution order: Secret Manager, then a key file on disk, then a freshly
    generated key persisted to disk.
    """
    settings = get_settings()
    secret_id = secret_id or settings.signing_key_secret

    pem = _secret_manager_pem(secret_id)
    if pem:
        private = load_private_key(pem)
        public_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        return pem, public_pem

    _LOCAL_KEY_DIR.mkdir(parents=True, exist_ok=True)
    key_path = _LOCAL_KEY_DIR / f"{secret_id}.pem"
    if key_path.exists():
        private_pem = key_path.read_text()
    else:
        private_pem, _ = generate_keypair()
        key_path.write_text(private_pem)
        key_path.chmod(0o600)
        logger.info("generated a new local signing key at %s", key_path)

    private = load_private_key(private_pem)
    public_pem = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem
