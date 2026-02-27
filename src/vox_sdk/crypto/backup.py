"""Passphrase-based key backup using scrypt + AES-256-GCM.

Uses the cryptography library which is a common dependency.
Falls back gracefully if not installed.
"""

from __future__ import annotations

import base64
import json
import os

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False


def _require_crypto() -> None:
    if not _HAS_CRYPTO:
        raise RuntimeError(
            "The 'cryptography' package is required for key backup. "
            "Install it with: pip install cryptography"
        )


_KDF_PARAMS: dict[int, dict[str, int]] = {
    1: {"n": 2**17, "r": 8, "p": 1},
}
_CURRENT_VERSION = 1


def encrypt_backup(data: bytes, passphrase: str) -> str:
    """Encrypt data with a passphrase. Returns a base64-encoded blob."""
    _require_crypto()

    params = _KDF_PARAMS[_CURRENT_VERSION]
    salt = os.urandom(16)

    kdf = Scrypt(salt=salt, length=32, n=params["n"], r=params["r"], p=params["p"])
    key = kdf.derive(passphrase.encode())

    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)

    envelope = {
        "v": _CURRENT_VERSION,
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ciphertext).decode(),
    }
    return base64.b64encode(json.dumps(envelope).encode()).decode()


def decrypt_backup(blob: str, passphrase: str) -> bytes:
    """Decrypt a backup blob with a passphrase."""
    _require_crypto()

    envelope = json.loads(base64.b64decode(blob))
    version = envelope.get("v")
    if version not in _KDF_PARAMS:
        raise ValueError(f"Unsupported backup format version: {version}")

    params = _KDF_PARAMS[version]
    salt = base64.b64decode(envelope["salt"])
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ct"])

    kdf = Scrypt(salt=salt, length=32, n=params["n"], r=params["r"], p=params["p"])
    key = kdf.derive(passphrase.encode())

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)
