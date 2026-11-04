"""Loading of the optional `cryptography` dependency.

Defines: `require_crypto`, which returns the AES and key-unwrap primitives or
raises an actionable `MissingCryptoError`.
Used by: core.ios_crypto, core.android_backup.
Depends on: core.errors, cryptography (lazily).

WHY a module of its own: iOS and Android decryption both need it, and an
unencrypted backup must stay processable without the package installed.
"""

from __future__ import annotations

import sys
from typing import Any

from core.errors import MissingCryptoError


def require_crypto() -> tuple[Any, Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
    except ImportError as exc:
        raise MissingCryptoError(
            "Encrypted backups require the 'cryptography' package. "
            f"It is not available to the current Python interpreter: {sys.executable}. "
            "Install and run with: uv sync; uv run python main.py, or "
            "activate the virtual environment before launching."
        ) from exc
    return Cipher, algorithms, modes, aes_key_unwrap
