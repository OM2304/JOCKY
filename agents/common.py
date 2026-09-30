"""Shared helpers for the JOCKY agent fabric.

Keeps path bootstrap in ONE place so `python agents/controller.py` and
`python agents/client.py` work from the repo root without installation.
"""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import hashlib
import json
import uuid

from jocky.crypto import decrypt as jycrypt_decrypt  # noqa: E402
from jocky.crypto import encrypt as jycrypt_encrypt  # noqa: E402
from jocky.crypto import new_key  # noqa: E402


def task_id() -> str:
    """Short unique task identifier."""
    return uuid.uuid4().hex[:12]


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def now_iso() -> str:
    """RFC-ish timestamp without third-party dateutil."""
    import time as _t
    return _t.strftime("%Y-%m-%dT%H:%M:%S%z")


def key_from_env(envvar: str = "JOCKY_KEY") -> bytes:
    """Payload decryption key from an env var (hex), or raise."""
    raw = os.environ.get(envvar)
    if not raw:
        raise RuntimeError(f"{envvar} not set (hex key required)")
    return bytes.fromhex(raw.strip())


def json_bytes(obj) -> bytes:
    return json.dumps(obj).encode("utf-8")